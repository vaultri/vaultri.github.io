//! URIs `otpauth://` — lo que hay dentro de los QR que enseñan los servicios.
//!
//! No existe un estándar formal, solo la convención que fijó Google
//! Authenticator y que todo el mundo copió con variaciones. El parser es
//! deliberadamente tolerante al leer y estricto al escribir.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::totp::{self, Algorithm};
use crate::vault::{Entry, SecretBytes};

const SCHEME: &str = "otpauth://totp/";

/// Decodifica un secreto en base32, tolerando relleno, espacios y minúsculas.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(char::to_uppercase)
        .collect();
    if cleaned.is_empty() {
        return Err(Error::InvalidEntry("secreto vacío"));
    }
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::InvalidEntry("secreto no es base32"))
}

/// Codifica un secreto en base32 sin relleno, que es como lo esperan los
/// lectores de QR.
pub fn encode_secret(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

/// Interpreta una URI `otpauth://totp/...`. Los campos ausentes toman los
/// valores por defecto de facto: SHA-1, 6 dígitos, 30 segundos.
pub fn parse_uri(uri: &str) -> Result<Entry> {
    let rest = strip_scheme(uri).ok_or(Error::InvalidUri("esquema no es otpauth://totp/"))?;
    let (label, query) = match rest.split_once('?') {
        Some((label, query)) => (label, query),
        None => (rest, ""),
    };

    let label = percent_decode(label)?;
    // El label es "Issuer:Account" o solo "Account"; algunos emisores meten un
    // espacio tras los dos puntos.
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_string()), account.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value)?;

        // Un parámetro vacío, o sin `=` siquiera, no dice nada: se trata como
        // ausente y el campo se queda en su valor por defecto. Hay emisores que
        // los sueltan, y tumbar por eso un QR por lo demás correcto sería ser
        // estricto al leer, que es justo lo que este parser no quiere.
        if value.is_empty() {
            continue;
        }

        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_secret(&value)?),
            "issuer" => issuer = Some(value),
            "algorithm" => algorithm = Algorithm::parse(&value)?,
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| Error::InvalidUri("digits no es un número"))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| Error::InvalidUri("period no es un número"))?
            }
            // Parámetros desconocidos se ignoran: cada emisor añade los suyos.
            _ => {}
        }
    }

    let secret = secret.ok_or(Error::InvalidUri("falta el parámetro secret"))?;
    if !(totp::MIN_DIGITS..=totp::MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidUri("digits fuera de rango"));
    }
    if period == 0 {
        return Err(Error::InvalidUri("period no puede ser cero"));
    }

    // El parámetro `issuer` manda sobre el prefijo del label cuando ambos están
    // y difieren: es el que los emisores rellenan con cuidado.
    Ok(Entry {
        issuer: issuer.or(label_issuer).unwrap_or_default(),
        account,
        secret: SecretBytes::new(secret),
        algorithm,
        digits,
        period,
        updated_at: 0,
    })
}

/// Serializa una entrada como URI `otpauth://`, para exportar o generar un QR.
/// Incluye el secreto en claro: solo debe usarse en respuesta a una acción
/// explícita del usuario.
pub fn to_uri(entry: &Entry) -> String {
    let mut uri = String::from(SCHEME);
    if !entry.issuer.is_empty() {
        uri.push_str(&percent_encode(&entry.issuer));
        uri.push_str("%3A");
    }
    uri.push_str(&percent_encode(&entry.account));
    uri.push_str("?secret=");
    uri.push_str(&encode_secret(entry.secret.as_slice()));
    if !entry.issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode(&entry.issuer));
    }
    uri.push_str("&algorithm=");
    uri.push_str(entry.algorithm.as_str());
    uri.push_str("&digits=");
    uri.push_str(&alloc::string::ToString::to_string(&entry.digits));
    uri.push_str("&period=");
    uri.push_str(&alloc::string::ToString::to_string(&entry.period));
    uri
}

fn strip_scheme(uri: &str) -> Option<&str> {
    // El esquema es case-insensitive; el path que lo sigue, no.
    let prefix_len = SCHEME.len();
    if uri.len() >= prefix_len && uri[..prefix_len].eq_ignore_ascii_case(SCHEME) {
        Some(&uri[prefix_len..])
    } else {
        None
    }
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s
                    .get(i + 1..i + 3)
                    .ok_or(Error::InvalidUri("escape % incompleto"))?;
                let byte = u8::from_str_radix(hex, 16)
                    .map_err(|_| Error::InvalidUri("escape % inválido"))?;
                out.push(byte);
                i += 3;
            }
            // En un query string '+' es un espacio; en el path no, pero ningún
            // emisor real depende de un '+' literal en el label.
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|_| Error::InvalidUri("texto no es UTF-8"))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&data_encoding::HEXUPPER.encode(&[*byte]));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_uri() {
        let entry = parse_uri("otpauth://totp/GitHub:joshua?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
            .unwrap();

        assert_eq!(entry.issuer, "GitHub");
        assert_eq!(entry.account, "joshua");
        assert_eq!(entry.secret.as_slice(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    #[test]
    fn honours_explicit_parameters() {
        let entry = parse_uri(
            "otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();

        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.period, 60);
    }

    #[test]
    fn decodes_percent_escapes_in_the_label() {
        let entry =
            parse_uri("otpauth://totp/Big%20Corp:joshua%40germade.es?secret=JBSWY3DPEHPK3PXP")
                .unwrap();

        assert_eq!(entry.issuer, "Big Corp");
        assert_eq!(entry.account, "joshua@germade.es");
    }

    #[test]
    fn issuer_parameter_wins_over_the_label_prefix() {
        let entry =
            parse_uri("otpauth://totp/Viejo:joshua?secret=JBSWY3DPEHPK3PXP&issuer=Nuevo").unwrap();
        assert_eq!(entry.issuer, "Nuevo");
    }

    #[test]
    fn accepts_a_label_without_issuer() {
        let entry = parse_uri("otpauth://totp/joshua?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(entry.issuer, "");
        assert_eq!(entry.account, "joshua");
    }

    #[test]
    fn ignores_unknown_parameters() {
        assert!(
            parse_uri("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fx.test")
                .is_ok()
        );
    }

    #[test]
    fn empty_parameters_fall_back_to_the_defaults() {
        let entry =
            parse_uri("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&algorithm=&digits=&period=")
                .unwrap();

        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    #[test]
    fn an_empty_issuer_falls_back_to_the_label_prefix() {
        let entry = parse_uri("otpauth://totp/GitHub:yo?secret=JBSWY3DPEHPK3PXP&issuer=").unwrap();
        assert_eq!(entry.issuer, "GitHub");
    }

    #[test]
    fn parameters_without_a_value_are_ignored() {
        let entry = parse_uri("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&image").unwrap();
        assert_eq!(entry.digits, 6);
    }

    #[test]
    fn an_empty_secret_counts_as_missing() {
        // Tolerar el vacío no puede llegar a dar por buena una entrada sin
        // secreto.
        assert!(parse_uri("otpauth://totp/A?secret=").is_err());
        assert!(parse_uri("otpauth://totp/A?secret").is_err());
    }

    #[test]
    fn rejects_malformed_uris() {
        assert!(parse_uri("https://example.test/?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse_uri("otpauth://totp/A").is_err(), "sin secret");
        assert!(parse_uri("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&digits=4").is_err());
        assert!(parse_uri("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
        assert!(
            parse_uri("otpauth://totp/A?secret=1111").is_err(),
            "base32 inválido"
        );
    }

    #[test]
    fn tolerates_padded_and_lowercase_secrets() {
        assert_eq!(
            decode_secret("jbswy3dpehpk3pxp").unwrap(),
            decode_secret("JBSWY3DPEHPK3PXP").unwrap()
        );
        assert_eq!(
            decode_secret("JBSWY3DP EHPK3PXP").unwrap(),
            decode_secret("JBSWY3DPEHPK3PXP").unwrap()
        );
        assert_eq!(decode_secret("MFRGG===").unwrap(), b"abc");
    }

    #[test]
    fn uri_roundtrip() {
        let original = parse_uri(
            "otpauth://totp/Big%20Corp:joshua%40germade.es?secret=JBSWY3DPEHPK3PXP&digits=8",
        )
        .unwrap();
        let reparsed = parse_uri(&to_uri(&original)).unwrap();
        assert_eq!(reparsed, original);
    }
}
