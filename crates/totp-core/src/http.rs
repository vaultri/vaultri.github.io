//! Transporte HTTP mínimo.
//!
//! El core necesita hablar con un almacén remoto sin saber quién hace las
//! peticiones: en el navegador es `fetch`, en los tests es un doble en memoria,
//! y en el móvil será lo que traiga la plataforma. Aquí solo están los tipos y
//! el trait; ninguna implementación.
//!
//! La credencial no aparece por ningún lado a propósito. Quien implemente
//! [`HttpClient`] es el que añade el `Authorization` y el que se ocupa de
//! refrescar el token: el core nunca ve un access token, igual que el almacén
//! nunca ve una entrada en claro.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Patch,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Bytes tal cual: los objetos del vault son binarios, no texto.
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }

    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Self {
        Self::new(Method::Post, url).with_body(body)
    }

    pub fn patch(url: impl Into<String>, body: Vec<u8>) -> Self {
        Self::new(Method::Patch, url).with_body(body)
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Busca una cabecera sin distinguir mayúsculas, como manda HTTP.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// El cuerpo como texto, solo para diagnóstico: lo que devuelve Drive
    /// cuando algo falla es JSON con un mensaje.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Quien sepa hacer una petición HTTP.
///
/// `async` sin exigir `Send`: el cliente principal es WASM de un solo hilo, y
/// pedir futuros `Send` obligaría a envolver cosas que en el navegador no lo
/// son. Un fallo de red se devuelve como [`crate::Error::Storage`]; un HTTP con
/// código de error no es un `Err`, es una [`Response`] que quien llama
/// interpreta.
#[allow(async_fn_in_trait)]
pub trait HttpClient {
    async fn send(&self, request: Request) -> Result<Response>;
}
