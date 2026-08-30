//! HOTP (RFC 4226) y TOTP (RFC 6238).

extern crate alloc;

use alloc::string::String;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Función hash del HMAC. SHA-1 es lo que emite prácticamente todo el mundo;
/// las otras dos existen porque el RFC las contempla y algún emisor las usa.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        // Los emisores no se ponen de acuerdo en mayúsculas ni en el guion.
        let normalized: String = s
            .chars()
            .filter(|c| *c != '-')
            .flat_map(char::to_uppercase)
            .collect();
        match normalized.as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::InvalidEntry("algoritmo desconocido")),
        }
    }
}

/// Rango de dígitos que aceptamos. Por debajo de 6 el código es adivinable; por
/// encima de 10 la truncación dinámica de 31 bits ya no aporta más entropía.
pub const MIN_DIGITS: u8 = 6;
pub const MAX_DIGITS: u8 = 10;

/// Macro en vez de función genérica: los tres hashes no comparten un bound
/// cómodo de escribir, y aquí solo hace falta repetir tres líneas.
macro_rules! hmac_bytes {
    ($hash:ty, $key:expr, $message:expr) => {{
        // `new_from_slice` solo falla con longitudes de clave inválidas, y HMAC
        // acepta cualquier longitud: de ahí el expect.
        let mut mac =
            <Hmac<$hash>>::new_from_slice($key).expect("HMAC acepta claves de cualquier longitud");
        mac.update($message);
        mac.finalize().into_bytes().to_vec()
    }};
}

/// Genera el HOTP de un contador concreto (RFC 4226 §5.3).
pub fn hotp(secret: &[u8], counter: u64, digits: u8, algorithm: Algorithm) -> Result<String> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidEntry("número de dígitos fuera de rango"));
    }

    let message = counter.to_be_bytes();
    let mac = match algorithm {
        Algorithm::Sha1 => hmac_bytes!(sha1::Sha1, secret, &message),
        Algorithm::Sha256 => hmac_bytes!(sha2::Sha256, secret, &message),
        Algorithm::Sha512 => hmac_bytes!(sha2::Sha512, secret, &message),
    };

    // Truncación dinámica: el nibble bajo del último byte elige el offset.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);

    let modulus = 10u64.pow(u32::from(digits));
    Ok(format_zero_padded(u64::from(binary) % modulus, digits))
}

/// TOTP en un instante dado, expresado en segundos Unix.
pub fn totp_at(
    secret: &[u8],
    unix_time: u64,
    period: u32,
    digits: u8,
    algorithm: Algorithm,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidEntry("periodo cero"));
    }
    hotp(secret, unix_time / u64::from(period), digits, algorithm)
}

/// Segundos que le quedan de vida al código vigente en `unix_time`.
pub fn seconds_remaining(unix_time: u64, period: u32) -> u32 {
    if period == 0 {
        return 0;
    }
    period - (unix_time % u64::from(period)) as u32
}

/// Comprueba un código admitiendo `skew` ventanas de desfase a cada lado, que
/// es lo que absorbe el reloj desajustado del cliente. La comparación es en
/// tiempo constante y se recorren siempre todas las ventanas, para no filtrar
/// por tiempo *cuál* de ellas acertó.
pub fn verify(
    secret: &[u8],
    code: &str,
    unix_time: u64,
    period: u32,
    digits: u8,
    algorithm: Algorithm,
    skew: u32,
) -> Result<bool> {
    if period == 0 {
        return Err(Error::InvalidEntry("periodo cero"));
    }
    let counter = unix_time / u64::from(period);
    let skew = u64::from(skew);
    let mut found = 0u8;

    for candidate in counter.saturating_sub(skew)..=counter.saturating_add(skew) {
        let expected = hotp(secret, candidate, digits, algorithm)?;
        found |= expected.as_bytes().ct_eq(code.as_bytes()).unwrap_u8();
    }

    Ok(found == 1)
}

fn format_zero_padded(value: u64, digits: u8) -> String {
    let mut out = alloc::string::ToString::to_string(&value);
    while out.len() < usize::from(digits) {
        out.insert(0, '0');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226, apéndice D.
    #[test]
    fn rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                &hotp(secret, counter as u64, 6, Algorithm::Sha1).unwrap(),
                code
            );
        }
    }

    // RFC 6238, apéndice B. Cada algoritmo usa una semilla de longitud distinta.
    #[test]
    fn rfc6238_totp_vectors() {
        let sha1 = b"12345678901234567890";
        let sha256 = b"12345678901234567890123456789012";
        let sha512 = b"1234567890123456789012345678901234567890123456789012345678901234";

        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        for (time, want1, want256, want512) in cases {
            assert_eq!(
                totp_at(sha1, time, 30, 8, Algorithm::Sha1).unwrap(),
                want1,
                "sha1 @ {time}"
            );
            assert_eq!(
                totp_at(sha256, time, 30, 8, Algorithm::Sha256).unwrap(),
                want256,
                "sha256 @ {time}"
            );
            assert_eq!(
                totp_at(sha512, time, 30, 8, Algorithm::Sha512).unwrap(),
                want512,
                "sha512 @ {time}"
            );
        }
    }

    #[test]
    fn codes_are_zero_padded() {
        // El contador 2 de la tabla del RFC 4226 trunca a 137359152, que a 10
        // dígitos necesita un cero por delante.
        let code = hotp(b"12345678901234567890", 2, 10, Algorithm::Sha1).unwrap();
        assert_eq!(code, "0137359152");
    }

    #[test]
    fn digits_out_of_range_are_rejected() {
        assert!(hotp(b"secreto", 0, 5, Algorithm::Sha1).is_err());
        assert!(hotp(b"secreto", 0, 11, Algorithm::Sha1).is_err());
    }

    #[test]
    fn verify_accepts_within_skew_and_rejects_outside() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_109;
        let previous = totp_at(secret, now - 30, 30, 6, Algorithm::Sha1).unwrap();
        let far = totp_at(secret, now - 300, 30, 6, Algorithm::Sha1).unwrap();

        assert!(verify(secret, &previous, now, 30, 6, Algorithm::Sha1, 1).unwrap());
        assert!(!verify(secret, &previous, now, 30, 6, Algorithm::Sha1, 0).unwrap());
        assert!(!verify(secret, &far, now, 30, 6, Algorithm::Sha1, 1).unwrap());
    }

    #[test]
    fn remaining_seconds_counts_down_within_the_window() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    #[test]
    fn algorithm_parsing_is_lenient_about_case_and_dashes() {
        assert_eq!(Algorithm::parse("sha-256").unwrap(), Algorithm::Sha256);
        assert_eq!(Algorithm::parse("SHA1").unwrap(), Algorithm::Sha1);
        assert!(Algorithm::parse("md5").is_err());
    }
}
