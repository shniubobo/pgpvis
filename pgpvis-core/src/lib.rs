use std::collections::HashMap;
use std::iter::Iterator;

use pgp::{armor::Dearmor, packet::PacketParser};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
struct ParseOutput(HashMap<String, String>);

impl From<HashMap<String, String>> for ParseOutput {
    fn from(value: HashMap<String, String>) -> Self {
        Self(value)
    }
}

impl TryFrom<ParseOutput> for JsValue {
    type Error = Error;

    fn try_from(value: ParseOutput) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::to_value(&value)?)
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("failed to serialize to JsValue")]
    Serialization(#[from] serde_wasm_bindgen::Error),
    #[error("failed to parse packet")]
    Parse(#[from] pgp::errors::Error),
}

#[wasm_bindgen(js_name = parse_armored)]
pub fn parse_armored_js(message: &str) -> Result<JsValue, JsError> {
    Ok(parse_armored(message)?.try_into()?)
}

fn parse_armored(message: &str) -> Result<ParseOutput, Error> {
    let dearmor = Dearmor::new(message.as_bytes());
    let packet_parser = PacketParser::new(dearmor);
    let parse_output: HashMap<_, _> = packet_parser
        .enumerate()
        .map(|packet| match packet {
            (idx, Ok(packet)) => (idx.to_string(), format!("{packet:?}")),
            (idx, Err(err)) => (idx.to_string(), Error::from(err).to_string()),
        })
        .collect();
    Ok(parse_output.into())
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    fn test_parse_armored_js() {
        let parse_output = parse_armored(include_str!("../tests/data/linus.gpg.asc")).unwrap();
        console_log!("{parse_output:#?}")
    }
}
