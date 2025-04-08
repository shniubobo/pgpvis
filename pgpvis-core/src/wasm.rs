//! Functions exported to wasm.

use std::result::Result as StdResult;

use sequoia_openpgp::{
    armor,
    parse::{
        buffered_reader::{BufferedReader, Memory},
        Cookie, Dearmor, PacketParserBuilder, PacketParserResult, Parse,
    },
};
use wasm_bindgen::prelude::*;

use crate::convert::*;
use crate::error::*;
use crate::packet::*;
use crate::render::Node;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseOptions {
    pub dearmor: bool,
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOutput {
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub bytes: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub nodes: Vec<Node>,
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
        let field_lengths = Converter::field_lengths(&parser);
        let converter = Converter::new(&mut context, field_lengths);
        // TODO: Replace the `or_else` call with `?` after we remove
        // `AnyPacket::Unknown` and `Error::UnknownPacket`.
        let packet = converter.convert(&parser).or_else(|err| {
            if let Error::UnknownPacket { span, .. } = err {
                Ok(Span {
                    offset: span.offset,
                    length: span.length,
                    inner: AnyPacket::Unknown,
                })
            } else {
                Err(err)
            }
        })?;
        packet_sequence.0.push(packet);

        parser_result = parser.next()?.1
    }

    let nodes = Node::render(packet_sequence);

    Ok(ParseOutput { bytes, nodes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_user_id_openpgp_packet() {
        let options = ParseOptions { dearmor: false };
        let message = b"\xcd\x17John <john@example.com>";
        let ParseOutput { bytes, nodes } = parse(options, message).unwrap();

        assert_eq!(bytes, message); // Bytes are unchanged after the round-trip.
        assert_eq!(nodes.len(), 1);

        let expected_node = Node {
            span: Some(Span::new(0, 25, ())),
            text: "[13] User ID: John <john@example.com>".to_string(),
            children: vec![
                Node {
                    span: Some(Span::new(0, 2, ())),
                    text: "Header".to_string(),
                    children: vec![
                        Node {
                            span: Some(Span::new(0, 1, ())),
                            text: "CTB".to_string(),
                            children: vec![
                                Node {
                                    span: None,
                                    text: "Format: OpenPGP".to_string(),
                                    children: vec![],
                                },
                                Node {
                                    span: None,
                                    text: "Type ID: 13".to_string(),
                                    children: vec![],
                                },
                            ],
                        },
                        Node {
                            span: Some(Span::new(1, 1, ())),
                            text: "Length: 23 (Full)".to_string(),
                            children: vec![],
                        },
                    ],
                },
                Node {
                    span: Some(Span::new(2, 23, ())),
                    text: "Body".to_string(),
                    children: vec![Node {
                        span: Some(Span::new(2, 23, ())),
                        text: "User ID: John <john@example.com>".to_string(),
                        children: vec![],
                    }],
                },
            ],
        };

        assert_eq!(nodes[0], expected_node);
    }

    #[test]
    fn armored_single_user_id_packet() {
        let options = ParseOptions { dearmor: false };
        let message = b"\xb4\x17John <john@example.com>";
        let ParseOutput {
            bytes: bytes_exptected,
            nodes: nodes_expected,
        } = parse(options, message).unwrap();

        let options = ParseOptions { dearmor: true };
        let message = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

tBdKb2huIDxqb2huQGV4YW1wbGUuY29tPg==
-----END PGP PUBLIC KEY BLOCK-----
"#
        .as_bytes();
        let ParseOutput { bytes, nodes } = parse(options, message).unwrap();

        assert_eq!(bytes, bytes_exptected);
        assert_eq!(nodes, nodes_expected);
    }
}
