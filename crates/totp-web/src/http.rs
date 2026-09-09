//! `HttpClient` sobre una función de JavaScript.
//!
//! El core no sabe hacer peticiones y no debe saberlo: quien las hace es el
//! módulo `drive.js`, que es también quien tiene el token de Google y quien lo
//! renueva cuando caduca. Aquí solo se traduce entre los tipos de Rust y un
//! objeto plano de JS, para que el puente no imponga ninguna forma de
//! autenticarse: el día que la fase 3 hable con el dongle, cambia la función y
//! no cambia nada más.
//!
//! El contrato con JS es:
//!
//! ```js
//! async function send({ method, url, headers: [[nombre, valor], …], body }) {
//!   return { status, body }; // body como Uint8Array
//! }
//! ```

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use totp_core::error::{Error, Result};
use totp_core::http::{HttpClient, Request, Response};

pub struct JsHttp {
    send: Function,
}

impl JsHttp {
    pub fn new(send: Function) -> Self {
        Self { send }
    }
}

impl HttpClient for JsHttp {
    async fn send(&self, request: Request) -> Result<Response> {
        let description = describe_request(&request);

        let value = JsFuture::from(Promise::resolve(
            &self
                .send
                .call1(&JsValue::NULL, &to_js(request)?)
                .map_err(|err| failed(&description, &err))?,
        ))
        .await
        .map_err(|err| failed(&description, &err))?;

        from_js(&value).map_err(|err| failed(&description, &err))
    }
}

fn to_js(request: Request) -> Result<JsValue> {
    let object = Object::new();
    set(
        &object,
        "method",
        &JsValue::from_str(request.method.as_str()),
    )?;
    set(&object, "url", &JsValue::from_str(&request.url))?;

    let headers = Array::new();
    for (name, value) in &request.headers {
        headers.push(&Array::of2(
            &JsValue::from_str(name),
            &JsValue::from_str(value),
        ));
    }
    set(&object, "headers", &headers)?;

    let body = match &request.body {
        Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
        None => JsValue::NULL,
    };
    set(&object, "body", &body)?;

    Ok(object.into())
}

fn from_js(value: &JsValue) -> core::result::Result<Response, JsValue> {
    let status = Reflect::get(value, &JsValue::from_str("status"))?
        .as_f64()
        .ok_or_else(|| JsValue::from_str("la respuesta no trae status"))?;

    let body = Reflect::get(value, &JsValue::from_str("body"))?;
    let body = if body.is_null() || body.is_undefined() {
        Vec::new()
    } else {
        Uint8Array::new(&body).to_vec()
    };

    Ok(Response::new(status as u16, body))
}

fn set(object: &Object, key: &str, value: &JsValue) -> Result<()> {
    Reflect::set(object, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|_| Error::Storage("no se pudo construir la petición".to_string()))
}

/// Qué se pedía, sin la query: los parámetros llevan nombres de fichero, que
/// son hashes, y no hacen falta para entender un fallo de red.
fn describe_request(request: &Request) -> String {
    let url = request.url.split('?').next().unwrap_or(&request.url);
    format!("{} {url}", request.method.as_str())
}

fn failed(what: &str, error: &JsValue) -> Error {
    Error::Storage(format!("{what}: {}", describe(error)))
}

fn describe(error: &JsValue) -> String {
    if let Some(text) = error.as_string() {
        return text;
    }
    if let Ok(message) = Reflect::get(error, &JsValue::from_str("message"))
        && let Some(text) = message.as_string()
    {
        return text;
    }
    format!("{error:?}")
}
