use std::marker::PhantomData;
use std::result::Result as StdResult;

use sequoia_openpgp::{
    self as pgp,
    packet::header::BodyLength as PGPBodyLength,
    parse::{map::Field as PGPField, PacketParser, PacketParserBuilder, PacketParserResult, Parse},
};
use serde::{Serialize, Serializer};
use serde_repr::Serialize_repr;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

pub trait PacketType {
    const TYPE_ID: TypeID;
}

// `#[derive(Tsify)]` doesn't support serializing as `u8`.
#[wasm_bindgen]
// `Serialize_repr` is derived despite the use of `#[wasm_bindgen]`, so that
// `Serialize` can be derived on other structs that contain `TypeID`.
#[derive(Debug, PartialEq, Eq, Serialize_repr)]
#[repr(u8)]
pub enum TypeID {
    UserID = 13,
    Private60 = 60,
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct PacketSequence(pub Vec<Span<AnyPacket>>);

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Span<T> {
    pub offset: usize,
    pub length: usize,
    pub inner: T,
}

impl<T> Span<T> {
    pub fn new(offset: usize, length: usize, inner: T) -> Self {
        Self {
            offset,
            length,
            inner,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(untagged)]
pub enum AnyPacket {
    UserID(Packet<UserID>),
    Private60(Packet<Private60>),
    // TODO: Remove this after we add placeholders for each packet type.
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Packet<T>
where
    T: PacketType,
{
    pub header: Span<Header<T>>,
    pub body: Span<Body<T>>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "format")]
pub enum Header<T>
where
    T: PacketType,
{
    OpenPGP {
        ctb: Span<CTB<T>>,
        length: Span<OpenPGPLength>,
    },
    Legacy {
        ctb: Span<CTB<T>>,
        length: Span<LegacyLength>,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct CTB<T>
where
    T: PacketType,
{
    pub format: Format,
    #[serde(serialize_with = "CTB::<T>::serialize_type_id")]
    #[tsify(type = "TypeID")]
    type_id: (),
    packet_type: PhantomData<T>,
}

impl<T> CTB<T>
where
    T: PacketType,
{
    const TYPE_ID: TypeID = T::TYPE_ID;

    pub fn new(format: Format) -> Self {
        Self {
            format,
            type_id: (),
            packet_type: PhantomData,
        }
    }

    pub const fn type_id(&self) -> TypeID {
        Self::TYPE_ID
    }

    fn serialize_type_id<S>(_: &(), serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::TYPE_ID.serialize(serializer)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub enum Format {
    OpenPGP,
    Legacy,
}

impl From<&pgp::packet::header::CTB> for Format {
    fn from(value: &pgp::packet::header::CTB) -> Self {
        match *value {
            pgp::packet::header::CTB::New(_) => Self::OpenPGP,
            pgp::packet::header::CTB::Old(_) => Self::Legacy,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum OpenPGPLength {
    Full(u32),
    Partial(u32),
}

impl From<&PGPBodyLength> for OpenPGPLength {
    fn from(value: &PGPBodyLength) -> Self {
        match *value {
            PGPBodyLength::Full(length) => OpenPGPLength::Full(length),
            PGPBodyLength::Partial(length) => OpenPGPLength::Partial(length),
            PGPBodyLength::Indeterminate => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum LegacyLength {
    Full(u32),
    Indeterminate,
}

impl From<&PGPBodyLength> for LegacyLength {
    fn from(value: &PGPBodyLength) -> Self {
        match *value {
            PGPBodyLength::Full(length) => LegacyLength::Full(length),
            PGPBodyLength::Partial(_) => unreachable!(),
            PGPBodyLength::Indeterminate => LegacyLength::Indeterminate,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Body<T: PacketType>(pub T);

impl<T> From<T> for Body<T>
where
    T: PacketType,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct UserID {
    pub user_id: Span<String>,
}

impl PacketType for UserID {
    const TYPE_ID: TypeID = TypeID::UserID;
}

impl From<Span<&pgp::packet::UserID>> for UserID {
    fn from(value: Span<&pgp::packet::UserID>) -> Self {
        Self {
            user_id: Span {
                offset: value.offset,
                length: value.length,
                inner: String::from_utf8_lossy(value.inner.value()).to_string(),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Private60;

impl PacketType for Private60 {
    const TYPE_ID: TypeID = TypeID::Private60;
}

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error has been returned from [`pgp`].
    ///
    /// [`sequoia_openpgp`] currently returns [`anyhow::Error`], which is [bad
    /// practice and planned to be changed]. As a result, we have to also
    /// depend on [`anyhow::Error`].
    ///
    /// [bad practice and planned to be changed]:
    ///     https://gitlab.com/sequoia-pgp/sequoia/-/issues/1020
    #[error("failed to parse packet")]
    Parse(#[from] anyhow::Error),

    #[error("private or unimplemented packet; type id: {type_id}")]
    UnknownPacket { type_id: u8 },

    #[error("span {field} not found on packet type: {tag}")]
    SpanNotFound { field: usize, tag: pgp::packet::Tag },
}

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

/// Intermediate struct to convert [`PacketParser`] into [`Span<AnyPacket>`].
struct IntermediatePacket<'context, 'packet> {
    context: &'context mut Context,
    spans: Vec<PGPField<'packet>>,
    header: &'packet pgp::packet::Header,
    body: &'packet pgp::Packet,
}

impl<'c, 'p> IntermediatePacket<'c, 'p> {
    pub fn new(context: &'c mut Context, parser: &'p PacketParser) -> IntermediatePacket<'c, 'p> {
        let spans = parser.map().unwrap().iter().collect();
        let header = parser.header();
        let body = &parser.packet;
        Self {
            context,
            spans,
            header,
            body,
        }
    }
}

impl TryFrom<IntermediatePacket<'_, '_>> for Span<AnyPacket> {
    type Error = Error;

    fn try_from(mut value: IntermediatePacket) -> StdResult<Self, Self::Error> {
        value.convert_any_packet()
    }
}

impl IntermediatePacket<'_, '_> {
    const CTB_IDX: usize = 0;
    const LENGTH_IDX: usize = 1;
    const BODY_IDX: usize = 2;

    fn convert_any_packet(&mut self) -> Result<Span<AnyPacket>> {
        let offset = self.context.offset();
        let inner = match self.body {
            pgp::Packet::UserID(user_id) => AnyPacket::UserID(Packet {
                header: self.convert_header()?,
                body: self.convert_user_id(user_id)?,
            }),
            unknown_packet => {
                return Err(Error::UnknownPacket {
                    type_id: unknown_packet.tag().into(),
                })
            }
        };
        let length = self.context.offset() - offset;

        Ok(Span::new(offset, length, inner))
    }

    fn convert_header<T>(&mut self) -> Result<Span<Header<T>>>
    where
        T: PacketType,
    {
        let offset = self.context.offset();
        let header = {
            let ctb = self.convert_ctb()?;
            match self.header.ctb() {
                pgp::packet::header::CTB::New(_) => Header::OpenPGP {
                    ctb,
                    length: self.convert_openpgp_length()?,
                },
                pgp::packet::header::CTB::Old(_) => Header::Legacy {
                    ctb,
                    length: self.convert_legacy_length()?,
                },
            }
        };
        let length = self.context.offset() - offset;

        Ok(Span::new(offset, length, header))
    }

    fn convert_ctb<T>(&mut self) -> Result<Span<CTB<T>>>
    where
        T: PacketType,
    {
        let (offset, length) = self.advance_offset(Self::CTB_IDX)?;
        let ctb = CTB::new(self.header.ctb().into());

        Ok(Span::new(offset, length, ctb))
    }

    fn convert_openpgp_length(&mut self) -> Result<Span<OpenPGPLength>> {
        let (offset, length) = self.advance_offset(Self::LENGTH_IDX)?;
        let packet_length = self.header.length().into();

        Ok(Span::new(offset, length, packet_length))
    }

    fn convert_legacy_length(&mut self) -> Result<Span<LegacyLength>> {
        let (offset, length) = self.advance_offset(Self::LENGTH_IDX)?;
        let packet_length = self.header.length().into();

        Ok(Span::new(offset, length, packet_length))
    }

    fn convert_user_id(&mut self, user_id: &pgp::packet::UserID) -> Result<Span<Body<UserID>>> {
        let (offset, length) = self.advance_offset(Self::BODY_IDX)?;
        let user_id: UserID = Span::new(offset, length, user_id).into();
        let body = user_id.into();

        Ok(Span::new(offset, length, body))
    }

    fn advance_offset(&mut self, field: usize) -> Result<(usize, usize)> {
        let field = &self.spans.get(field).ok_or(Error::SpanNotFound {
            field,
            tag: self.body.tag(),
        })?;
        let offset = self.context.offset();
        let length = field.as_bytes().len();
        self.context.advance_offset(length);

        Ok((offset, length))
    }
}

/// Records the state of parsing.
struct Context {
    offset: usize,
}

impl Context {
    pub fn new() -> Self {
        Self { offset: 0 }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn advance_offset(&mut self, bytes: usize) {
        self.offset += bytes;
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn header_type_id_inferred_from_body() {
        let user_id = UserID {
            user_id: Span {
                offset: 2,
                length: 1,
                inner: "a".to_string(),
            },
        };
        let packet = Packet {
            header: Span {
                offset: 0,
                length: 2,
                inner: Header::Legacy {
                    ctb: Span {
                        offset: 0,
                        length: 1,
                        inner: CTB {
                            format: Format::Legacy,
                            type_id: (),
                            packet_type: PhantomData,
                        },
                    },
                    length: Span {
                        offset: 1,
                        length: 1,
                        inner: LegacyLength::Full(1),
                    },
                },
            },
            body: Span {
                offset: 2,
                length: 1,
                inner: Body(user_id),
            },
        };

        match packet.header.inner {
            Header::OpenPGP { .. } => unreachable!(),
            Header::Legacy { ctb, .. } => assert_eq!(ctb.inner.type_id(), TypeID::UserID),
        }
    }

    #[wasm_bindgen_test]
    fn single_user_id_openpgp_packet() {
        let message = b"\xcd\x17John <john@example.com>";
        let packet_sequence = parse(message).unwrap();
        let packet = &packet_sequence.0[0];

        let expected = Span {
            offset: 0,
            length: 25,
            inner: AnyPacket::UserID(Packet {
                header: Span {
                    offset: 0,
                    length: 2,
                    inner: Header::OpenPGP {
                        ctb: Span {
                            offset: 0,
                            length: 1,
                            inner: CTB {
                                format: Format::OpenPGP,
                                type_id: (),
                                packet_type: PhantomData,
                            },
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
                    inner: Body(UserID {
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
            inner: AnyPacket::UserID(Packet {
                header: Span {
                    offset: 0,
                    length: 2,
                    inner: Header::Legacy {
                        ctb: Span {
                            offset: 0,
                            length: 1,
                            inner: CTB {
                                format: Format::Legacy,
                                type_id: (),
                                packet_type: PhantomData,
                            },
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
                    inner: Body(UserID {
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
