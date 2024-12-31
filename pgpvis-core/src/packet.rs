//! OpenPGP-related data structures to be passed across the wasm boundary.

use std::marker::PhantomData;
use std::result::Result as StdResult;

use sequoia_openpgp::{self as pgp, packet::header::BodyLength as PgpBodyLength};
use serde::{Serialize, Serializer};
use serde_repr::Serialize_repr;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use crate::error::*;

/// Trait implemented by every struct that represents a certain type of packet.
///
/// This is necessary for a Type ID to be inferred during compile-time for each
/// [`Packet`].
pub trait PacketType {
    const TYPE_ID: TypeId;
}

macro_rules! gen_packet_type_impls {
    ( $packet_type:ident ) => {
        impl PacketType for $packet_type {
            const TYPE_ID: TypeId = TypeId::$packet_type;
        }
    };

    [ $( $packet_type:ident ),+ $(,)? ] => {
        $( gen_packet_type_impls!($packet_type); )+
    };
}

macro_rules! gen_type_id_enum {
    { $( $packet_type:ident = $type_id:literal ),+ $(,)? } => {
        /// Every possible Type ID as defined by [RFC 9580].
        ///
        /// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580#name-packet-types
        // `#[derive(Tsify)]` doesn't support serializing as `u8`.
        #[wasm_bindgen]
        // `Serialize_repr` is derived despite the use of `#[wasm_bindgen]`, so
        // that `Serialize` can be derived on other structs that contain `TypeID`.
        #[derive(Debug, PartialEq, Eq, Serialize_repr)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum TypeId {
            $( $packet_type = $type_id ),+
        }
    };
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

macro_rules! gen_any_packet_enum {
    [ $( $packet_type:ident ),+ $(,)? ] => {
        /// Enum of every type of packet.
        ///
        /// This is necessary if we need to fit packets into a single data
        /// structure, such as a [`Vec`].
        #[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
        #[serde(untagged)]
        #[non_exhaustive]
        pub enum AnyPacket {
            $( $packet_type(Packet<$packet_type>), )+
            // TODO: Remove this after we add placeholders for each packet type.
            Unknown,
        }
    };
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
#[serde(tag = "format")]
pub enum Header<T>
where
    T: PacketType,
{
    #[serde(rename = "OpenPGP")]
    OpenPgp {
        ctb: Span<OpenPgpCtb<T>>,
        length: Span<OpenPgpLength>,
    },
    Legacy {
        ctb: Span<LegacyCtb<T>>,
        length: Span<LegacyLength>,
    },
}

/// OpenPGP format newtype variant of [`Ctb`].
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct OpenPgpCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> OpenPgpCtb<T>
where
    T: PacketType,
{
    pub fn from_openpgp(ctb: &pgp::packet::header::CTB) -> Result<Self> {
        match ctb {
            pgp::packet::header::CTB::New(_) => Ok(Self(Ctb::new())),
            pgp::packet::header::CTB::Old(_) => Err(Error::WrongFormat {
                expected: "OpenPGP".to_string(),
                got: "Legacy".to_string(),
            }),
        }
    }

    fn from_legacy(_ctb: &pgp::packet::header::CTB) -> Result<Self> {
        Err(Error::Unimplemented)
    }
}

impl<T> From<&pgp::packet::header::CTB> for OpenPgpCtb<T>
where
    T: PacketType,
{
    fn from(ctb: &pgp::packet::header::CTB) -> Self {
        Self::from_openpgp(ctb)
            .or_else(|_| Self::from_legacy(ctb))
            .unwrap()
    }
}

impl<T> From<OpenPgpCtb<T>> for Ctb<T>
where
    T: PacketType,
{
    fn from(value: OpenPgpCtb<T>) -> Self {
        value.0
    }
}

/// Legacy format newtype variant of [`Ctb`].
#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct LegacyCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> LegacyCtb<T>
where
    T: PacketType,
{
    fn from_openpgp(_ctb: &pgp::packet::header::CTB) -> Result<Self> {
        Err(Error::Unimplemented)
    }

    pub fn from_legacy(ctb: &pgp::packet::header::CTB) -> Result<Self> {
        match ctb {
            pgp::packet::header::CTB::New(_) => Err(Error::WrongFormat {
                expected: "Legacy".to_string(),
                got: "OpenPGP".to_string(),
            }),
            pgp::packet::header::CTB::Old(_) => Ok(Self(Ctb::new())),
        }
    }
}

impl<T> From<&pgp::packet::header::CTB> for LegacyCtb<T>
where
    T: PacketType,
{
    fn from(ctb: &pgp::packet::header::CTB) -> Self {
        Self::from_openpgp(ctb)
            .or_else(|_| Self::from_legacy(ctb))
            .unwrap()
    }
}

impl<T> From<LegacyCtb<T>> for Ctb<T>
where
    T: PacketType,
{
    fn from(value: LegacyCtb<T>) -> Self {
        value.0
    }
}

/// The first byte of each header.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Tsify)]
pub struct Ctb<T>
where
    T: PacketType,
{
    #[serde(serialize_with = "Ctb::<T>::serialize_type_id")]
    #[tsify(type = "TypeID")]
    type_id: (),
    #[serde(skip)]
    packet_type: PhantomData<T>,
}

impl<T> Ctb<T>
where
    T: PacketType,
{
    const TYPE_ID: TypeId = T::TYPE_ID;

    pub fn new() -> Self {
        Self {
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

/// Marker trait for [`OpenPgpLength`] and [`LegacyLength`].
pub(crate) trait Length {}
impl Length for OpenPgpLength {}
impl Length for LegacyLength {}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum OpenPgpLength {
    Full(u32),
    Partial(u32),
}

impl TryFrom<&pgp::packet::Header> for OpenPgpLength {
    type Error = Error;

    fn try_from(header: &pgp::packet::Header) -> StdResult<Self, Self::Error> {
        if let pgp::packet::header::CTB::Old(_) = header.ctb() {
            return Err(Error::WrongFormat {
                expected: "OpenPGP".to_string(),
                got: "Legacy".to_string(),
            });
        };

        let length = match *header.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(length) => Self::Partial(length),
            PgpBodyLength::Indeterminate => unreachable!(),
        };
        Ok(length)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum LegacyLength {
    Full(u32),
    Indeterminate,
}

impl TryFrom<&pgp::packet::Header> for LegacyLength {
    type Error = Error;

    fn try_from(header: &pgp::packet::Header) -> StdResult<Self, Self::Error> {
        if let pgp::packet::header::CTB::New(_) = header.ctb() {
            return Err(Error::WrongFormat {
                expected: "Legacy".to_string(),
                got: "OpenPGP".to_string(),
            });
        };

        let length = match *header.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(_) => unreachable!(),
            PgpBodyLength::Indeterminate => Self::Indeterminate,
        };
        Ok(length)
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
pub struct UserId {
    pub user_id: Span<String>,
}

impl From<Span<&pgp::packet::UserID>> for UserId {
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

macro_rules! gen_packet_enums_and_impls {
    { $( $packet_type:ident = $type_id:literal ),+ $(,)? } => {
        gen_packet_type_impls![$( $packet_type ),+];

        gen_type_id_enum! {
            $( $packet_type = $type_id ),+
        }

        gen_any_packet_enum![$( $packet_type ),+];
    };
}

gen_packet_enums_and_impls! {
    UserId = 13,
    Private60 = 60,
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn header_type_id_inferred_from_body() {
        let user_id = UserId {
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
                        inner: LegacyCtb(Ctb {
                            type_id: (),
                            packet_type: PhantomData,
                        }),
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
            Header::Legacy { ctb, .. } => assert_eq!(ctb.inner.0.type_id(), TypeId::UserId),
        }
    }
}
