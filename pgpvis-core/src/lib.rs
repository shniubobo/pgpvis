use std::iter::Iterator;

use pgp::{
    armor::Dearmor,
    packet::{PacketParser, PacketTrait},
};
use serde::Serialize;
use tsify_next::{declare, Tsify};
use wasm_bindgen::prelude::*;

#[declare]
pub type Message = Vec<Packet>;

#[derive(Debug, Serialize, Tsify)]
#[tsify(into_wasm_abi)]
pub enum Packet {
    UserId(UserId),
    Unknown,
}

impl From<pgp::packet::Packet> for Packet {
    fn from(value: pgp::packet::Packet) -> Self {
        use pgp::packet::Packet as RpgpPacket;
        match value {
            RpgpPacket::UserId(user_id) => Self::UserId(user_id.into()),
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Serialize, Tsify)]
pub struct UserId {
    pub packet_version: Version,
    pub id: String,
}

impl From<pgp::packet::UserId> for UserId {
    fn from(value: pgp::packet::UserId) -> Self {
        Self {
            packet_version: value.packet_version().into(),
            id: value.id().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Tsify)]
pub enum Version {
    Old,
    New,
}

impl From<pgp::types::Version> for Version {
    fn from(value: pgp::types::Version) -> Self {
        match value {
            pgp::types::Version::Old => Self::Old,
            pgp::types::Version::New => Self::New,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("failed to parse packet")]
    Parse(#[from] pgp::errors::Error),
}

#[wasm_bindgen]
pub fn parse_armored(message: &str) -> Result<Message, JsError> {
    let dearmor = Dearmor::new(message.as_bytes());
    let packet_parser = PacketParser::new(dearmor);
    let parse_output: Result<Vec<Packet>, Error> = packet_parser
        .map(|packet| match packet {
            Ok(packet) => Ok(packet.into()),
            Err(err) => Err(err.into()),
        })
        .collect();
    Ok(parse_output?)
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    fn test_parse_armored_js() {
        let parse_output = parse_armored(include_str!("../tests/data/linus.gpg.asc")).unwrap();
        for packet in parse_output {
            if let Packet::UserId(user_id) = packet {
                let packet_version = user_id.packet_version;
                let id = user_id.id;
                console_log!("{packet_version:?}: {id}");
            }
        }
    }
}
