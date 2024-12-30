//! OpenPGP-related data structures to be passed across the wasm boundary.

use std::marker::PhantomData;
use std::result::Result as StdResult;

use sequoia_openpgp::{self as pgp, packet::header::BodyLength as PgpBodyLength};
use serde::{Serialize, Serializer};
use serde_repr::Serialize_repr;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

/// Trait implemented by every struct that represents a certain type of packet.
///
/// This is necessary for a Type ID to be inferred during compile-time for each
/// [`Packet`].
pub trait PacketType {
    const TYPE_ID: TypeId;
}

/// Every possible Type ID as defined by [RFC 9580].
///
/// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580#name-packet-types
// `#[derive(Tsify)]` doesn't support serializing as `u8`.
#[wasm_bindgen]
// `Serialize_repr` is derived despite the use of `#[wasm_bindgen]`, so that
// `Serialize` can be derived on other structs that contain `TypeID`.
#[derive(Debug, PartialEq, Eq, Serialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum TypeId {
    UserId = 13,
    Private60 = 60,
}

/// Newtype for [`Vec<Span<AnyPacket>>`].
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct PacketSequence(pub Vec<Span<AnyPacket>>);

/// Information of where a [`Packet`], [`Header`], [`Body`], etc., or a header
/// or body field, is located inside an OpenPGP message.
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

/// Enum of every type of packet.
///
/// This is necessary if we need to fit packets into a single data structure,
/// such as a [`Vec`].
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(untagged)]
#[non_exhaustive]
pub enum AnyPacket {
    UserId(Packet<UserID>),
    Private60(Packet<Private60>),
    // TODO: Remove this after we add placeholders for each packet type.
    Unknown,
}

/// An OpenPGP packet, including the header and the body.
///
/// The type parameter `T` ensures that [`header`](Self::header) and
/// [`body`](Self::body) are of the same packet type at compile-time.
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Packet<T>
where
    T: PacketType,
{
    pub header: Span<Header<T>>,
    pub body: Span<Body<T>>,
}

/// The first few bytes of a packet which specifies its format and length.
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(untagged)]
pub enum Header<T>
where
    T: PacketType,
{
    OpenPgp {
        ctb: Span<Ctb<T>>,
        length: Span<OpenPGPLength>,
    },
    Legacy {
        ctb: Span<Ctb<T>>,
        length: Span<LegacyLength>,
    },
}

/// The first byte of each header.
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Ctb<T>
where
    T: PacketType,
{
    pub format: Format,
    #[serde(serialize_with = "Ctb::<T>::serialize_type_id")]
    #[tsify(type = "TypeID")]
    type_id: (),
    packet_type: PhantomData<T>,
}

impl<T> Ctb<T>
where
    T: PacketType,
{
    const TYPE_ID: TypeId = T::TYPE_ID;

    pub fn new(format: Format) -> Self {
        Self {
            format,
            type_id: (),
            packet_type: PhantomData,
        }
    }

    pub const fn type_id(&self) -> TypeId {
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
    // This should be `OpenPgp` by convention of Rust, but we are using
    // `OpenPGP` here, so that we don't need to write a custom serializing
    // function, or tamper with `Tsify` to create the right string in `.d.ts`.
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

impl From<&PgpBodyLength> for OpenPGPLength {
    fn from(value: &PgpBodyLength) -> Self {
        match *value {
            PgpBodyLength::Full(length) => OpenPGPLength::Full(length),
            PgpBodyLength::Partial(length) => OpenPGPLength::Partial(length),
            PgpBodyLength::Indeterminate => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum LegacyLength {
    Full(u32),
    Indeterminate,
}

impl From<&PgpBodyLength> for LegacyLength {
    fn from(value: &PgpBodyLength) -> Self {
        match *value {
            PgpBodyLength::Full(length) => LegacyLength::Full(length),
            PgpBodyLength::Partial(_) => unreachable!(),
            PgpBodyLength::Indeterminate => LegacyLength::Indeterminate,
        }
    }
}

/// A packet, without its [`Header`].
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
    const TYPE_ID: TypeId = TypeId::UserId;
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
    const TYPE_ID: TypeId = TypeId::Private60;
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
                        inner: Ctb {
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
            Header::OpenPgp { .. } => unreachable!(),
            Header::Legacy { ctb, .. } => assert_eq!(ctb.inner.type_id(), TypeId::UserId),
        }
    }
}
