//! Functions exported to wasm.

use std::result::Result as StdResult;

use sequoia_openpgp::{
    armor,
    parse::{
        buffered_reader::{BufferedReader, Memory},
        Cookie, Dearmor, PacketParserBuilder, PacketParserResult, Parse,
    },
};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use crate::convert::*;
use crate::error::*;
use crate::packet::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Tsify)]
#[tsify(from_wasm_abi)]
pub struct ParseOptions {
    pub dearmor: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct ParseOutput {
    pub bytes: Vec<u8>,
    pub packet_sequence: PacketSequence,
}

/// Parses a OpenPGP message as defined in [RFC 9580].
///
/// - `options`: Options deciding how the message should be parsed.
/// - `message`: Either armored or unarmored message. If armored and
///   [`options.dearmor`](ParseOptions::dearmor) is `true`, the message will be
///   dearmored before being further parsed.
///
/// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580
#[wasm_bindgen(js_name = "parse")]
pub fn parse_js(options: ParseOptions, message: &[u8]) -> StdResult<ParseOutput, JsError> {
    Ok(parse(options, message)?)
}

// This is necessary instead of putting `#[wasm_bindgen]` directly here, or
// otherwise we have to call `.map_err(Error::from)` every time we write `?`,
// because `anyhow::Error: Into<JsError>` is not satisfied. This won't be
// necessary when `sequoia_openpgp` stops returning `anyhow::Error` in the
// future. See also the doc on `Error::Parse`.
fn parse(options: ParseOptions, message: &[u8]) -> Result<ParseOutput> {
    let mut message_unarmored;
    if options.dearmor {
        message_unarmored =
            armor::Reader::from_reader(message, armor::ReaderMode::Tolerant(None)).into_boxed();
    } else {
        message_unarmored = Memory::with_cookie(message, Cookie::default()).into_boxed();
    }
    let bytes = message_unarmored.data_eof()?.to_vec();

    let mut parser_result = PacketParserBuilder::from_buffered_reader(message_unarmored)
        .unwrap()
        .dearmor(Dearmor::Disabled)
        .map(true)
        .build()?;
    let mut packet_sequence = PacketSequence(vec![]);
    let mut context = Context::new();

    while let PacketParserResult::Some(parser) = parser_result {
        let converter = Converter::new(&mut context, &parser);
        // TODO: Replace the `or_else` call with `?` after we remove
        // `AnyPacket::Unknown` and `Error::UnknownPacket`.
        packet_sequence.0.push(converter.convert().or_else(|err| {
            if let Error::UnknownPacket { span, .. } = err {
                Ok(Span {
                    offset: span.offset,
                    length: span.length,
                    inner: AnyPacket::Unknown,
                })
            } else {
                Err(err)
            }
        })?);

        parser_result = parser.next()?.1
    }

    Ok(ParseOutput {
        bytes,
        packet_sequence,
    })
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn single_user_id_openpgp_packet() {
        let options = ParseOptions { dearmor: false };
        let message = b"\xcd\x17John <john@example.com>";
        let packet_sequence = parse(options, message).unwrap().packet_sequence;
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
                            inner: OpenPgpCtb(Ctb::new()),
                        },
                        length: Span {
                            offset: 1,
                            length: 1,
                            inner: OpenPgpLength::Full(23),
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
        let options = ParseOptions { dearmor: false };
        let message = b"\xb4\x17John <john@example.com>";
        let packet_sequence = parse(options, message).unwrap().packet_sequence;
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
                            inner: LegacyCtb(Ctb::new()),
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
        let options = ParseOptions { dearmor: false };
        let message = b"\xb4\x17John <john@example.com>";
        let packet_sequence = parse(options, message).unwrap().packet_sequence;
        let expected = &packet_sequence.0[0];

        let options = ParseOptions { dearmor: true };
        let message = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

tBdKb2huIDxqb2huQGV4YW1wbGUuY29tPg==
-----END PGP PUBLIC KEY BLOCK-----
            "#
        .as_bytes();
        let packet_sequence = parse(options, message).unwrap().packet_sequence;
        let packet = &packet_sequence.0[0];

        assert_eq!(packet, expected);
    }
}
