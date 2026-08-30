use core::fmt;

/// Error único del core. Deliberadamente pobre en detalles en todo lo que
/// toca material criptográfico: distinguir "MAC inválido" de "passphrase
/// incorrecta" solo sirve para dar pistas a quien tenga el blob cifrado.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// El descifrado falló: clave incorrecta, datos manipulados o AAD que no
    /// corresponde. No se distingue entre los tres a propósito.
    Decrypt,
    /// Derivación de clave fallida (parámetros de Argon2id fuera de rango).
    KeyDerivation,
    /// La fuente de entropía del sistema no está disponible.
    Entropy,
    /// Un campo del formato serializado no cuadra (longitud, versión, tipo).
    Format(&'static str),
    /// Versión de formato que este binario no sabe leer.
    UnsupportedVersion(u32),
    /// No hay ningún envoltorio de la MK que se corresponda con la credencial
    /// aportada.
    NoMatchingWrapper,
    /// Entrada TOTP inválida (secreto no base32, dígitos fuera de rango...).
    InvalidEntry(&'static str),
    /// URI `otpauth://` mal formada.
    InvalidUri(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decrypt => f.write_str("no se pudo descifrar"),
            Error::KeyDerivation => f.write_str("derivación de clave fallida"),
            Error::Entropy => f.write_str("entropía del sistema no disponible"),
            Error::Format(what) => write!(f, "formato inválido: {what}"),
            Error::UnsupportedVersion(v) => write!(f, "versión de formato no soportada: {v}"),
            Error::NoMatchingWrapper => f.write_str("ningún envoltorio coincide con la credencial"),
            Error::InvalidEntry(what) => write!(f, "entrada inválida: {what}"),
            Error::InvalidUri(what) => write!(f, "URI otpauth inválida: {what}"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
