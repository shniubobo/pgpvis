//! Functions exported to wasm.

use std::result::Result as StdResult;

use sequoia_openpgp::parse::{PacketParserBuilder, PacketParserResult, Parse};
use wasm_bindgen::prelude::*;

use crate::convert::*;
use crate::error::*;
use crate::packet::*;

/// Parses a OpenPGP message as defined in [RFC 9580].
///
/// - `message`: Either armored or unarmored message. If armored, it is
///   automatically dearmored.
///
/// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580
#[wasm_bindgen(js_name = "parse")]
pub fn parse_js(message: &[u8]) -> StdResult<PacketSequence, JsError> {
    Ok(parse(message)?)
}

// This is necessary instead of putting `#[wasm_bindgen]` directly here, or
// otherwise we have to call `.map_err(Error::from)` every time we write `?`,
// because `anyhow::Error: Into<JsError>` is not satisfied. This won't be
// necessary when `sequoia_openpgp` stops returning `anyhow::Error` in the
// future. See also the doc on `Error::Parse`.
fn parse(message: &[u8]) -> Result<PacketSequence> {
    let mut parser_result = PacketParserBuilder::from_bytes(message)
        .unwrap()
        .map(true)
        .build()?;
    let mut packet_sequence = PacketSequence(vec![]);
    let mut context = Context::new();

    while let PacketParserResult::Some(parser) = parser_result {
        let packet = IntermediatePacket::new(&mut context, &parser);
        // TODO: Replace the `unwrap_or` call with `?` after we remove
        // `AnyPacket::Unknown`.
        packet_sequence.0.push(packet.try_into().unwrap_or(Span {
            offset: 0,
            length: 0,
            inner: AnyPacket::Unknown,
        }));

        parser_result = parser.next()?.1
    }

    Ok(packet_sequence)
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn single_user_id_openpgp_packet() {
        let message = b"\xcd\x17John <john@example.com>";
        let packet_sequence = parse(message).unwrap();
        let packet = &packet_sequence.0[0];

        let expected = Span {
            offset: 0,
            length: 25,
            inner: AnyPacket::UserId(Packet {
                header: Span {
                    offset: 0,
                    length: 2,
                    inner: Header::OpenPgp {
                        ctb: Span {
                            offset: 0,
                            length: 1,
                            inner: Ctb::new(Format::OpenPGP),
                        },
                        length: Span {
                            offset: 1,
                            length: 1,
                            inner: OpenPGPLength::Full(23),
                        },
                    },
                },
                body: Span {
                    offset: 2,
                    length: 23,
                    inner: Body(UserId {
                        user_id: Span {
                            offset: 2,
                            length: 23,
                            inner: "John <john@example.com>".to_string(),
                        },
                    }),
                },
            }),
        };

        assert_eq!(*packet, expected);
    }

    #[wasm_bindgen_test]
    fn single_user_id_legacy_packet() {
        let message = b"\xb4\x17John <john@example.com>";
        let packet_sequence = parse(message).unwrap();
        let packet = &packet_sequence.0[0];

        let expected = Span {
            offset: 0,
            length: 25,
            inner: AnyPacket::UserId(Packet {
                header: Span {
                    offset: 0,
                    length: 2,
                    inner: Header::Legacy {
                        ctb: Span {
                            offset: 0,
                            length: 1,
                            inner: Ctb::new(Format::Legacy),
                        },
                        length: Span {
                            offset: 1,
                            length: 1,
                            inner: LegacyLength::Full(23),
                        },
                    },
                },
                body: Span {
                    offset: 2,
                    length: 23,
                    inner: Body(UserId {
                        user_id: Span {
                            offset: 2,
                            length: 23,
                            inner: "John <john@example.com>".to_string(),
                        },
                    }),
                },
            }),
        };

        assert_eq!(*packet, expected);
    }

    #[wasm_bindgen_test]
    fn armored_single_user_id_packet() {
        let message = b"\xb4\x17John <john@example.com>";
        let packet_sequence = parse(message).unwrap();
        let expected = &packet_sequence.0[0];

        let message = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

tBdKb2huIDxqb2huQGV4YW1wbGUuY29tPg==
-----END PGP PUBLIC KEY BLOCK-----
            "#
        .as_bytes();
        let packet_sequence = parse(message).unwrap();
        let packet = &packet_sequence.0[0];

        assert_eq!(packet, expected);
    }
}
