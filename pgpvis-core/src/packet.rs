//! OpenPGP-related data structures to be passed across the wasm boundary.
//!
//! Some types in this module contains fields of `()`, which means the actual
//! value should be accessed via a getter method, and the sole reason that the
//! field exists is to allow [`Serialize`] and [`Tsify`] to be correctly
//! derived.
//!
//! Some types in this module implement [`Display`] to generate each packet's
//! summary line.

use std::marker::PhantomData;
use std::result::Result as StdResult;

use derive_more::with_trait::Display;
use serde::{Serialize, Serializer};
use serde_repr::Serialize_repr;
use tsify_next::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

/// Newtype for [`Vec<Span<AnyPacket>>`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct PacketSequence(pub Vec<Span<AnyPacket>>);

/// Trait implemented by every struct that represents a certain type of packet.
///
/// This is necessary for a Type ID to be inferred during compile-time for each
/// [`Packet`].
pub trait PacketType: Display {
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
        #[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize_repr)]
        #[display("{:02}", *self as u8)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum TypeId {
            $( $packet_type = $type_id ),+
        }
    };
}

macro_rules! gen_any_packet_enum {
    [ $( $packet_type:ident ),+ $(,)? ] => {
        /// Enum of every type of packet.
        ///
        /// This is necessary if we need to fit packets into a single data
        /// structure, such as a [`Vec`].
        #[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
        #[display("{}", _0)]
        #[serde(untagged)]
        #[non_exhaustive]
        pub enum AnyPacket {
            $( $packet_type(Packet<$packet_type>), )+
            // TODO: Remove this after we add placeholders for each packet type.
            #[display("Unknown")]
            Unknown,
        }
    };
}

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
    Reserved = 0,
    PublicKey = 6,
    UserId = 13,
    PublicSubkey = 14,
    Private60 = 60,
}

/// Information of where a [`Packet`], [`Header`], [`Body`], etc., or a header
/// or body field, is located inside an OpenPGP message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Tsify)]
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

    /// Convert the inner value into `U`, keeping the span info.
    pub fn transpose<U>(self) -> Span<U>
    where
        T: Into<U>,
    {
        let (span, inner) = self.take();
        span.replace_with(inner.into())
    }

    /// Take the inner value, returning a new [`Span`] without an inner
    /// value, and the old inner.
    fn take(self) -> (Span<()>, T) {
        (self.replace_with(()), self.inner)
    }

    /// Return a new [`Span`] with a new [`inner`](Self::inner) field.
    fn replace_with<U>(&self, new_inner: U) -> Span<U> {
        Span {
            offset: self.offset,
            length: self.length,
            inner: new_inner,
        }
    }
}

// This is currently only used by `Error::UnknownPacket`, which may be
// removed in the future.
//
// TODO: Remove this when it's no longer needed.
impl<T> Display for Span<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.offset, self.length)
    }
}

/// An OpenPGP packet, including the header and the body.
///
/// The type parameter `T` ensures that [`header`](Self::header) and
/// [`body`](Self::body) are of the same packet type at compile-time.
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("{}", self.body.inner.0)]
pub struct Packet<T>
where
    T: PacketType,
{
    pub header: Span<Header<T>>,
    pub body: Span<Body<T>>,
}

/// The first few bytes of a packet which specifies its format and length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
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

impl<T> Copy for Header<T> where T: PacketType + Clone {}

/// OpenPGP format newtype variant of [`Ctb`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct OpenPgpCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> Copy for OpenPgpCtb<T> where T: PacketType + Clone {}

/// Legacy format newtype variant of [`Ctb`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct LegacyCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> Copy for LegacyCtb<T> where T: PacketType + Clone {}

/// The first byte of each header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Ctb<T>
where
    T: PacketType,
{
    #[serde(serialize_with = "Ctb::<T>::serialize_type_id")]
    #[tsify(type = "TypeId")]
    type_id: (),
    #[serde(skip)]
    packet_type: PhantomData<T>,
}

// Cannot be derived for all `T: PacketType`.
impl<T> Default for Ctb<T>
where
    T: PacketType,
{
    fn default() -> Self {
        Self {
            type_id: (),
            packet_type: PhantomData,
        }
    }
}

impl<T> Copy for Ctb<T> where T: PacketType + Clone {}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum OpenPgpLength {
    Full(u32),
    Partial(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Tsify)]
#[serde(tag = "encoding", content = "length")]
pub enum LegacyLength {
    Full(u32),
    Indeterminate,
}

/// A packet, without its [`Header`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Body<T: PacketType>(pub T);

impl<T> From<T> for Body<T>
where
    T: PacketType,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// Enum for every kind of public keys, each variant being a combination of
/// a certain version and algorithm.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("{}", _0)]
#[serde(untagged)]
#[non_exhaustive]
pub enum PublicKey {
    Version4RsaEncryptSign(PublicVersion4<Key, RsaEncryptSign>),
    Version4Ed25519(PublicVersion4<Key, Ed25519>),
}

/// Enum for every kind of public subkeys, each variant being a combination of
/// a certain version and algorithm.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("{}", _0)]
#[serde(untagged)]
#[non_exhaustive]
pub enum PublicSubkey {
    Version4RsaEncryptSign(PublicVersion4<Subkey, RsaEncryptSign>),
    Version4Ed25519(PublicVersion4<Subkey, Ed25519>),
}

/// The public part of a version 4 key or subkey.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display(
    "[{}] Public {} ({}): {}",
    R::PUBLIC_TYPE_ID,
    self.role,
    self.key_material.inner,
    self.key_id,
)]
pub struct PublicVersion4<R, A>
where
    R: KeyRole,
    A: PublicKeyAlgorithm,
{
    /// Marker field for key role, either [`Key`] or [`Subkey`].
    #[serde(skip)]
    pub(crate) role: R,

    #[serde(serialize_with = "PublicVersion4::<R, A>::serialize_version")]
    #[tsify(type = "Span<4>")]
    pub(crate) version: Span<()>,

    pub creation_time: Span<Time>,

    #[serde(serialize_with = "PublicVersion4::<R, A>::serialize_algorithm")]
    #[tsify(type = "Span<PublicKeyAlgorithmId>")]
    pub(crate) algorithm: Span<()>,

    pub key_material: Span<A>,

    /// The Key ID of the key or subkey.
    ///
    /// This is not directly stored in a packet, but rather calculated by the
    /// implementation from the key. However, it may be useful to store this
    /// information here instead of on-the-fly calculation.
    pub key_id: String,
}

impl<R, A> PublicVersion4<R, A>
where
    R: KeyRole,
    A: PublicKeyAlgorithm,
{
    pub const VERSION: u8 = 4;

    pub fn new(
        version_span: Span<()>,
        creation_time: Span<Time>,
        algorithm_span: Span<()>,
        key_material: Span<A>,
        key_id: String,
    ) -> Self {
        Self {
            role: R::default(),
            version: version_span,
            creation_time,
            algorithm: algorithm_span,
            key_material,
            key_id,
        }
    }

    fn serialize_version<S>(version: &Span<()>, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Span { offset, length, .. } = *version;
        Span {
            offset,
            length,
            inner: Self::VERSION,
        }
        .serialize(serializer)
    }

    fn serialize_algorithm<S>(algorithm: &Span<()>, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Span { offset, length, .. } = *algorithm;
        Span {
            offset,
            length,
            inner: A::ID,
        }
        .serialize(serializer)
    }
}

/// Marker trait for [`Key`] and [`Subkey`].
pub trait KeyRole: Default + Display {
    /// The Type ID for public key or subkey.
    const PUBLIC_TYPE_ID: TypeId;
    // TODO: /// The Type ID for secret key or subkey.
    // const SECRET_TYPE_ID: u8;
}

/// Marker struct for primary keys.
#[derive(Clone, Copy, Debug, Display, Default, PartialEq, Eq, Serialize)]
pub struct Key;
impl KeyRole for Key {
    const PUBLIC_TYPE_ID: TypeId = PublicKey::TYPE_ID;
}

/// Marker struct for subkeys.
#[derive(Clone, Copy, Debug, Display, Default, PartialEq, Eq, Serialize)]
pub struct Subkey;
impl KeyRole for Subkey {
    const PUBLIC_TYPE_ID: TypeId = PublicSubkey::TYPE_ID;
}

/// Trait implemented by every public key algorithm struct.
pub trait PublicKeyAlgorithm: Display {
    const ID: PublicKeyAlgorithmId;
}

macro_rules! gen_public_key_algorithm_impls {
    ( $algorithm:ident ) => {
        impl PublicKeyAlgorithm for $algorithm {
            const ID: PublicKeyAlgorithmId = PublicKeyAlgorithmId::$algorithm;
        }
    };

    [ $( $algorithm:ident ),+ $(,)? ] => {
        $( gen_public_key_algorithm_impls!($algorithm); )+
    };
}

macro_rules! gen_public_key_algorithm_id_enum {
    { $( $algorithm:ident = $algorithm_id:literal ),+ $(,)? } => {
        /// Every possible ID of public key algorithms as defined by [RFC 9580].
        ///
        /// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580#section-9.1
        #[wasm_bindgen]
        #[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize_repr)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum PublicKeyAlgorithmId {
            $( $algorithm = $algorithm_id ),+
        }
    };
}

macro_rules! gen_public_key_algorithm_enums_and_impls {
    { $( $algorithm:ident = $algorithm_id:literal ),+ $(,)? } => {
        gen_public_key_algorithm_impls![$( $algorithm ),+];

        gen_public_key_algorithm_id_enum! {
            $( $algorithm = $algorithm_id ),+
        }
    };
}

gen_public_key_algorithm_enums_and_impls! {
    RsaEncryptSign = 1,
    Ed25519 = 27,
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("RSA (Encrypt or Sign)")]
pub struct RsaEncryptSign {
    pub n: Span<Mpi>,
    pub e: Span<Mpi>,
}

impl RsaEncryptSign {
    pub fn new(n: Span<Mpi>, e: Span<Mpi>) -> Self {
        Self { n, e }
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("Ed25519")]
pub struct Ed25519(pub Span<[u8; 32]>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Mpi {
    pub length: Span<u16>,
    pub integers: Span<Vec<u8>>,
}

impl Mpi {
    pub fn new(length: Span<u16>, integers: Span<Vec<u8>>) -> Self {
        Self { length, integers }
    }
}

/// Newtype of [`u32`], representing seconds since the unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Tsify)]
pub struct Time(pub u32);

impl Time {
    pub fn new(secs_since_epoch: u32) -> Self {
        Self(secs_since_epoch)
    }
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("[{}] User ID: {}", Self::TYPE_ID, self.user_id.inner)]
pub struct UserId {
    pub user_id: Span<String>,
}

impl UserId {
    pub fn new(user_id: Span<String>) -> Self {
        Self { user_id }
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("[{}] Reserved", Self::TYPE_ID)]
pub struct Reserved;

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, Tsify)]
#[display("[{}] Private", Self::TYPE_ID)]
pub struct Private60;

#[cfg(test)]
mod tests {
    use super::*;

    use paste::paste;

    /// Generate tests that each assert the display string of a type.
    ///
    /// To call this macro:
    ///
    /// ```text
    /// assert_display! {
    ///     [function name of test] {
    ///         [expression that constructs a type instance]
    ///     } => [expected display string]
    ///
    ///     [repeat for other tests]
    /// }
    /// ```
    ///
    /// `display_` is prepended to the name of each test.
    macro_rules! assert_display {
        {$( $fn_name:ident $from:tt => $expected:literal )*} => {
            $(
                paste! {
                    #[test]
                    fn [<display_ $fn_name>] () {
                        let string = $from.to_string();
                        assert_eq!(string, $expected);
                    }
                }
            )*
        };
    }

    macro_rules! dummy_span {
        ( $inner:expr ) => {
            Span {
                offset: 0,
                length: 0,
                inner: $inner,
            }
        };
    }

    macro_rules! dummy_mpi {
        () => {
            Mpi {
                length: dummy_span!(0),
                integers: dummy_span!(vec![]),
            }
        };
    }

    // Only one test is written for each `#[display(...)]` or mannual impl.
    assert_display! {
        type_id {
            TypeId::Reserved
        } => "00"

        any_packet {
            AnyPacket::UserId(
                Packet {
                    header: dummy_span!(
                        Header::Legacy {
                            ctb: dummy_span!(
                                LegacyCtb(Ctb {
                                    type_id: (),
                                    packet_type: PhantomData,
                                })
                            ),
                            length: dummy_span!(LegacyLength::Full(1)),
                        }
                    ),
                    body: dummy_span!(
                        Body(UserId {
                            user_id: dummy_span!("a".to_string()),
                        })
                    ),
                }
            )
        } => "[13] User ID: a"

        any_packet_unknown {
            AnyPacket::Unknown
        } => "Unknown"

        packet {
            Packet {
                header: dummy_span!(
                    Header::Legacy {
                        ctb: dummy_span!(
                            LegacyCtb(Ctb {
                                type_id: (),
                                packet_type: PhantomData,
                            })
                        ),
                        length: dummy_span!(LegacyLength::Full(1)),
                    }
                ),
                body: dummy_span!(
                    Body(UserId {
                        user_id: dummy_span!("a".to_string()),
                    })
                ),
            }
        } => "[13] User ID: a"

        public_key {
            PublicKey::Version4Ed25519(
                PublicVersion4 {
                    role: Key,
                    version: dummy_span!(()),
                    creation_time: dummy_span!(Time(0)),
                    algorithm: dummy_span!(()),
                    key_material: dummy_span!(Ed25519(dummy_span!([0; 32]))),
                    key_id: "DEADBEEFDEADBEEF".to_string(),
                }
            )
        } => "[06] Public Key (Ed25519): DEADBEEFDEADBEEF"

        public_subkey {
            PublicSubkey::Version4Ed25519(
                PublicVersion4 {
                    role: Subkey,
                    version: dummy_span!(()),
                    creation_time: dummy_span!(Time(0)),
                    algorithm: dummy_span!(()),
                    key_material: dummy_span!(Ed25519(dummy_span!([0; 32]))),
                    key_id: "DEADBEEFDEADBEEF".to_string(),
                }
            )
        } => "[14] Public Subkey (Ed25519): DEADBEEFDEADBEEF"

        public_version_4 {
            PublicVersion4 {
                role: Key,
                version: dummy_span!(()),
                creation_time: dummy_span!(Time(0)),
                algorithm: dummy_span!(()),
                key_material: dummy_span!(Ed25519(dummy_span!([0; 32]))),
                key_id: "DEADBEEFDEADBEEF".to_string(),
            }
        } => "[06] Public Key (Ed25519): DEADBEEFDEADBEEF"

        key {
            Key
        } => "Key"

        subkey {
            Subkey
        } => "Subkey"

        rsa_encrypt_sign {
            RsaEncryptSign {
                n: dummy_span!(dummy_mpi!()),
                e: dummy_span!(dummy_mpi!()),
            }
        } => "RSA (Encrypt or Sign)"

        ed25519 {
            Ed25519(dummy_span!([0; 32]))
        } => "Ed25519"

        user_id {
            UserId { user_id: dummy_span!("a".to_string()) }
        } => "[13] User ID: a"

        reserved {
            Reserved
        } => "[00] Reserved"

        private_60 {
            Private60
        } => "[60] Private"
    }

    #[test]
    fn span_transpose() {
        struct A;
        #[derive(Debug, PartialEq, Eq)]
        struct B;
        impl From<A> for B {
            fn from(_a: A) -> Self {
                B
            }
        }

        let span_a = Span::new(0, 1, A);
        let span_b = span_a.transpose();

        let expected = Span::new(0, 1, B);
        assert_eq!(span_b, expected);
    }

    #[test]
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
