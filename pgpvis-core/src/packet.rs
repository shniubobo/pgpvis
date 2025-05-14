//! OpenPGP-related data structures, as the intermediate representation after
//! [`convert`](crate::convert)ing and before [`render`](crate::render)ing.
//!
//! Some types in this module contains fields of `()`, which means the actual
//! value should be accessed via a getter method, and the sole reason that the
//! field exists is to allow [`Serialize`] to be correctly derived.
//!
//! [`Serialize`] is derived on most types in this module. Historically, this
//! was to make them `Tsify`-derivable and to make them snapshottable by
//! [`insta`]. However, as the dependency on `tsify` (`tsify-next`, actually)
//! has been dropped during `pgpvis` v0.2, the latter has become the sole
//! reason for these [`Serialize`]s to linger on the heads of so many types.
//!
//! Some types in this module implement [`Display`] to help
//! [`render`](crate::render)ing.

use std::marker::PhantomData;
use std::result::Result as StdResult;

use derive_more::with_trait::{Display, From, TryFrom};
use enumflags2::{bitflags, BitFlags};
use serde::{Serialize, Serializer};
use serde_repr::Serialize_repr;

use crate::error::*;

/// Newtype for [`Vec<Span<AnyPacket>>`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
        #[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
        #[display("{}", _0)]
        #[serde(untagged)]
        #[non_exhaustive]
        pub enum AnyPacket {
            $( $packet_type(Packet<$packet_type>), )+
            // TODO: Remove this after we add placeholders for each packet type.
            #[display("Unimplemented")]
            Unimplemented,
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
    Signature = 2,
    PublicKey = 6,
    UserId = 13,
    PublicSubkey = 14,
    Private60 = 60,
}

/// Information of where a [`Packet`], [`Header`], [`Body`], etc., or a header
/// or body field, is located inside an OpenPGP message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Span<T>
where
    T: ?Sized,
{
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
    pub fn take(self) -> (Span<()>, T) {
        (self.replace_with(()), self.inner)
    }

    /// Return a new [`Span`] with a new [`inner`](Self::inner) field.
    pub fn replace_with<U>(&self, new_inner: U) -> Span<U> {
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
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[display("{}", self.body.inner.0)]
pub struct Packet<T>
where
    T: PacketType,
{
    pub header: Span<Header<T>>,
    pub body: Span<Body<T>>,
}

/// The first few bytes of a packet which specifies its format and length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OpenPgpCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> Copy for OpenPgpCtb<T> where T: PacketType + Clone {}

/// Legacy format newtype variant of [`Ctb`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LegacyCtb<T>(pub Ctb<T>)
where
    T: PacketType;

impl<T> Copy for LegacyCtb<T> where T: PacketType + Clone {}

/// The first byte of each header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ctb<T>
where
    T: PacketType,
{
    #[serde(serialize_with = "Ctb::<T>::serialize_type_id")]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "encoding", content = "length")]
pub enum OpenPgpLength {
    Full(u32),
    Partial(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "encoding", content = "length")]
pub enum LegacyLength {
    Full(u32),
    Indeterminate,
}

/// A packet, without its [`Header`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Body<T: PacketType>(pub T);

impl<T> From<T> for Body<T>
where
    T: PacketType,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize, From)]
#[non_exhaustive]
pub enum Signature {
    Version4RsaEncryptSign(SignatureVersion4<RsaEncryptSign>),
    Version4EdDsaLegacy(SignatureVersion4<EdDsaLegacy>),
    Version4Ed25519(SignatureVersion4<Ed25519>),
    Version4Unimplemented(SignatureVersion4<PublicKeyAlgorithmUnimplemented>),
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display(
    "[{}][{:02}] {}",
    Signature::TYPE_ID,
    type_id.inner as u8,
    type_id.inner,
)]
pub struct SignatureVersion4<A>
where
    A: PublicKeyAlgorithm,
{
    pub version: Span<PhantomData<u8>>,
    pub type_id: Span<SignatureTypeId>,
    pub pub_key_algo_id: Span<PhantomData<A>>,
    pub hash_algo_id: Span<HashAlgorithmId>,
    pub hashed_length: Span<u16>,
    pub hashed_subpackets: Span<SignatureSubpackets>,
    pub unhashed_length: Span<u16>,
    pub unhashed_subpackets: Span<SignatureSubpackets>,
    pub hash_prefix: Span<[u8; 2]>,
    pub mpis: Span<A::SignatureMpis>,
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum SignatureTypeId {
    #[display("Binary Signature")]
    Binary = 0x00,

    #[display("Text Signature")]
    Text = 0x01,

    #[display("Standalone Signature")]
    Standalone = 0x02,

    #[display("Generic Certification Signature")]
    GenericCertification = 0x10,

    #[display("Persona Certification Signature")]
    PersonaCertification = 0x11,

    #[display("Casual Certification Signature")]
    CasualCertification = 0x12,

    #[display("Positive Certification Signature")]
    PositiveCertification = 0x13,

    #[display("Subkey Binding Signature")]
    SubkeyBinding = 0x18,

    #[display("Primary Key Binding Signature")]
    PrimaryKeyBinding = 0x19,

    #[display("Direct Key Signature")]
    DirectKey = 0x1F,

    #[display("Key Revocation Signature")]
    KeyRevocation = 0x20,

    #[display("Subkey Revocation Signature")]
    SubkeyRevocation = 0x28,

    #[display("Certification Revocation Signature")]
    CertificationRevocation = 0x30,

    #[display("Timestamp Signature")]
    Timestamp = 0x40,

    #[display("Third-Party Confirmation Signature")]
    ThirdPartyConfirmation = 0x50,

    Reserved = 0xFF,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, From)]
pub struct SignatureSubpackets(pub Vec<Span<SignatureSubpacket>>);

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display("[{}] {}", data.inner.type_id(), data.inner)]
pub struct SignatureSubpacket {
    pub length: Span<SignatureSubpacketLength>,
    pub type_id: Span<SignatureSubpacketTypeIdOctet>,
    pub data: Span<SignatureSubpacketData>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SignatureSubpacketLength {
    One(u8),
    Two(u8, u8),
    Five(u8, u32),
}

impl SignatureSubpacketLength {
    pub const TWO_MASK: u8 = 192;
    pub const FIVE_MASK: u8 = 255;

    pub const fn n_octets(&self) -> u8 {
        match self {
            SignatureSubpacketLength::One(..) => 1,
            SignatureSubpacketLength::Two(..) => 2,
            SignatureSubpacketLength::Five(..) => 5,
        }
    }

    pub const fn first(&self) -> u8 {
        match self {
            Self::One(first) | Self::Two(first, _) | Self::Five(first, _) => *first,
        }
    }

    pub const fn is_valid(&self) -> bool {
        match self {
            SignatureSubpacketLength::One(octet) => Self::is_one(*octet),
            SignatureSubpacketLength::Two(first, _) => Self::is_two(*first),
            SignatureSubpacketLength::Five(first, _) => Self::is_five(*first),
        }
    }

    pub const fn is_one(first: u8) -> bool {
        first < Self::TWO_MASK
    }

    pub const fn is_two(first: u8) -> bool {
        Self::TWO_MASK <= first && first < Self::FIVE_MASK
    }

    pub const fn is_five(first: u8) -> bool {
        first == Self::FIVE_MASK
    }
}

impl TryFrom<SignatureSubpacketLength> for u32 {
    type Error = Error;

    fn try_from(length: SignatureSubpacketLength) -> Result<Self> {
        use SignatureSubpacketLength as Length;

        if !length.is_valid() {
            return Err(Error::WrongSignatureSubpacketLengthEncoding {
                length: length.n_octets(),
                first: length.first(),
            });
        }

        Ok(match length {
            Length::One(octet) => octet as _,
            Length::Two(first, second) => {
                const MASK: u32 = Length::TWO_MASK as _;
                ((first as u32 - MASK) << 8) + second as u32 + MASK
            }
            Length::Five(_, rest) => rest,
        })
    }
}

// TODO:
//
// 1. Rename `SignatureSubpacketData` to `AnySignatureSubpacketData`;
// 2. Generate a newtype struct for each of its variants, make them implement
//    `trait SignatureSubpacketData`, which has a constant `TYPE_ID`;
// 3. Give this type a generic parameter `S: SignatureSubpacketData`, and put
//    that into the `PhantomData`.
//
// These are to make it possible to calculate the actual byte without passing
// in a `SignatureSubpacketData`. The second step would require a proc macro.
// `newtype-enum` exists for this purpose, but it is unmaintained, with lots of
// features missing, so we would need to fork it to make necessary amendments.
//
// Given that there is little need to convert this type back to a byte, this
// may be unnecessary complexity. However, this has been a common pattern
// within the crate, so the benefits provided by such a proc macro could be
// greater than the efforts needed.
//
// [Refinement / pattern types] would also fit in this use case, but it is
// still at an early stage, only aims for integer range patterns, and will not
// enter stable in the near future.
//
// [Refinement / pattern types]:
//     https://github.com/rust-lang/rust/issues/123646
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureSubpacketTypeIdOctet {
    pub critical: bool,
    pub type_id: PhantomData<u8>,
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SignatureSubpacketData {
    #[display("Signature Creation Time")]
    SignatureCreationTime(Span<Time>),

    #[display("Signature Expiration Time")]
    SignatureExpirationTime(Span<Time>),

    #[display("Exportable Certification")]
    ExportableCertification(Span<bool>),

    #[display("Trust Signature")]
    TrustSignature { level: Span<u8>, amount: Span<u8> },

    #[display("Regular Expression")]
    RegularExpression(Span<String>),

    #[display("Revocable")]
    Revocable(Span<bool>),

    #[display("Key Expiration Time")]
    KeyExpirationTime(Span<Time>),

    #[display("Preferred Symmetric Ciphers for v1 SEIPD")]
    PreferredSymmetricCiphers(Span<Vec<Span<SymmetricKeyAlgorithmId>>>),

    #[display("Revocation Key (deprecated)")]
    RevocationKey {
        class: Span<u8>,
        pub_key_algo_id: Span<PublicKeyAlgorithmId>,
        fingerprint: Span<FingerprintVersion4>,
    },

    #[display("Issuer Key ID")]
    IssuerKeyId(Span<KeyId>),

    #[display("Notation Data")]
    NotationData {
        flags: Span<BitFlags<NotationDataFlag>>,
        name_length: Span<u16>,
        value_length: Span<u16>,
        name: Span<String>,
        value: Span<Vec<u8>>,
    },

    #[display("Preferred Hash Algorithms")]
    PreferredHashAlgorithms(Span<Vec<Span<HashAlgorithmId>>>),

    #[display("Preferred Compression Algorithms")]
    PreferredCompressionAlgorithms(Span<Vec<Span<CompressionAlgorithmId>>>),

    #[display("Key Server Preferences")]
    KeyServerPreferences(Span<KeyServerPreferencesFlags>),

    #[display("Preferred Key Server")]
    PreferredKeyServer(Span<String>),

    #[display("Primary User ID")]
    PrimaryUserId(Span<bool>),

    #[display("Policy URI")]
    PolicyUri(Span<String>),

    #[display("Key Flags")]
    KeyFlags(Span<KeyFlagsFlags>),

    #[display("Signer's User ID")]
    SignerUserId(Span<String>),

    #[display("Reason for Revocation")]
    RevocationReason {
        code: Span<RevocationCode>,
        reason: Span<String>,
    },

    #[display("Features")]
    Features(Span<FeaturesFlags>),

    #[display("Signature Target")]
    SignatureTarget {
        pub_key_algo_id: Span<PublicKeyAlgorithmId>,
        hash_algo_id: Span<HashAlgorithmId>,
        hash: Span<Vec<u8>>,
    },

    #[display("Embedded Signature")]
    // Using `Box` to reduce variant size.
    EmbeddedSignature(Span<Box<Signature>>),

    #[display("Issuer Fingerprint")]
    IssuerFingerprint {
        version: Span<PhantomData<u8>>,
        fingerprint: Span<Fingerprint>,
    },

    #[display("Intended Recipient Fingerprint")]
    IntendedRecipientFingerprint {
        version: Span<PhantomData<u8>>,
        fingerprint: Span<Fingerprint>,
    },

    #[display("Preferred AEAD Ciphersuites")]
    PreferredAeadCiphersuites(Span<Vec<Span<AeadCiphersuite>>>),
}

macro_rules! gen_subpacket_type_ids {
    { $( $name:ident $member:tt = $id:literal ),* $(,)? } => {
        impl SignatureSubpacketData {
            pub const fn type_id(&self) -> u8 {
                match self {
                    $( Self::$name $member => $id, )*
                }
            }
        }

        #[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
        #[try_from(repr)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum SignatureSubpacketTypeId {
            $( $name = $id, )*
        }
    };
}

gen_subpacket_type_ids! {
    SignatureCreationTime(_) = 2,
    SignatureExpirationTime(_) = 3,
    ExportableCertification(_) = 4,
    TrustSignature { .. } = 5,
    RegularExpression(_) = 6,
    Revocable(_) = 7,
    KeyExpirationTime(_) = 9,
    PreferredSymmetricCiphers(_) = 11,
    RevocationKey { .. } = 12,
    IssuerKeyId(_) = 16,
    NotationData { .. } = 20,
    PreferredHashAlgorithms(_) = 21,
    PreferredCompressionAlgorithms(_) = 22,
    KeyServerPreferences(_) = 23,
    PreferredKeyServer(_) = 24,
    PrimaryUserId(_) = 25,
    PolicyUri(_) = 26,
    KeyFlags(_) = 27,
    SignerUserId(_) = 28,
    RevocationReason { .. } = 29,
    Features(_) = 30,
    SignatureTarget { .. } = 31,
    EmbeddedSignature(_) = 32,
    IssuerFingerprint { .. } = 33,
    IntendedRecipientFingerprint { .. } = 35,
    PreferredAeadCiphersuites(_) = 39,
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[bitflags]
#[repr(u32)]
pub enum NotationDataFlag {
    #[display("Notation value is UTF-8 text")]
    HumanReadable = 0x8000_0000,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KeyServerPreferencesFlags(pub Span<BitFlags<KeyServerPreferencesFlags0>>);

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[bitflags]
#[repr(u8)]
pub enum KeyServerPreferencesFlags0 {
    #[display(
        "The keyholder requests that this key only be modified or updated by \
        the keyholder or an administrator of the key server."
    )]
    NoModify = 0x80,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KeyFlagsFlags(
    pub Span<BitFlags<KeyFlagsFlags0>>,
    pub Span<BitFlags<KeyFlagsFlags1>>,
);

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[bitflags]
#[repr(u8)]
pub enum KeyFlagsFlags0 {
    #[display(
        "This key may be used to make User ID certifications or Direct Key \
        signatures over other keys."
    )]
    Certify = 0x01,

    #[display("This key may be used to sign data.")]
    Sign = 0x02,

    #[display("This key may be used to encrypt communications.")]
    EncryptCommunication = 0x04,

    #[display("This key may be used to encrypt storage.")]
    EncryptStorage = 0x08,

    #[display(
        "The private component of this key may have been split by a \
        secret-sharing mechanism."
    )]
    PrivateSplit = 0x10,

    #[display("This key may be used for authentication.")]
    Authenticate = 0x20,

    #[display(
        "The private component of this key may be in the possession of more \
        than one person."
    )]
    PrivateShared = 0x80,
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[bitflags]
#[repr(u8)]
pub enum KeyFlagsFlags1 {
    #[display("Reserved (ADSK)")]
    Reserved04 = 0x04,

    #[display("Reserved (timestamping)")]
    Reserved08 = 0x08,
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum RevocationCode {
    #[display("No reason specified")]
    NoReason = 0,

    #[display("Key is superseded")]
    Superseded = 1,

    #[display("Key material has been compromised")]
    Compromised = 2,

    #[display("Key is retired and no longer used")]
    Retired = 3,

    #[display("User ID information is no longer valid")]
    UserIdInvalid = 32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FeaturesFlags(pub Span<BitFlags<FeaturesFlags0>>);

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[bitflags]
#[repr(u8)]
pub enum FeaturesFlags0 {
    #[display("Version 1 SEIPD packet")]
    SeipdVersion1 = 0x01,

    #[display("Reserved")]
    Reserved02 = 0x02,

    #[display("Reserved")]
    Reserved04 = 0x04,

    #[display("Version 2 SEIPD packet")]
    SeipdVersion2 = 0x08,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, From)]
pub struct AeadCiphersuite(pub Span<SymmetricKeyAlgorithmId>, pub Span<AeadAlgorithmId>);

pub trait SignatureMpis: Serialize {
    const DISPLAY: &'static str;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureMpisRsa(pub Span<Mpi>);
impl SignatureMpis for SignatureMpisRsa {
    const DISPLAY: &'static str = "Algorithm-specific fields for RSA signatures";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureMpisRS {
    pub r: Span<Mpi>,
    pub s: Span<Mpi>,
}
impl SignatureMpis for SignatureMpisRS {
    const DISPLAY: &'static str =
        "Algorithm-specific fields for DSA, ECDSA or EdDSALegacy (Ed25519Legacy) signatures";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureMpisEd25519(
    #[serde(serialize_with = "<Span<[_]>>::serialize")] pub Span<[u8; 64]>,
);
impl SignatureMpis for SignatureMpisEd25519 {
    const DISPLAY: &'static str = "Algorithm-specific fields for Ed25519 signatures";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureMpisEd448(
    #[serde(serialize_with = "<Span<[_]>>::serialize")] pub Span<[u8; 114]>,
);
impl SignatureMpis for SignatureMpisEd448 {
    const DISPLAY: &'static str = "Algorithm-specific fields for Ed448 signatures";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignatureMpisUnimplemented;
impl SignatureMpis for SignatureMpisUnimplemented {
    const DISPLAY: &'static str =
        "Algorithm-specific fields for signatures of unimplemented algorithms";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum SignatureMpisNever {}
impl SignatureMpis for SignatureMpisNever {
    const DISPLAY: &'static str =
        "Non-existent algorithm-specific signature fields for algorithms uncapable to sign";
}

/// Enum for every kind of public keys, each variant being a combination of
/// a certain version and algorithm.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum PublicKey {
    Version4RsaEncryptSign(PublicVersion4<Key, RsaEncryptSign>),
    Version4Ecdh(PublicVersion4<Key, Ecdh>),
    Version4EdDsaLegacy(PublicVersion4<Key, EdDsaLegacy>),
    Version4X25519(PublicVersion4<Key, X25519>),
    Version4Ed25519(PublicVersion4<Key, Ed25519>),
    Version4Unimplemented(PublicVersion4<Key, PublicKeyAlgorithmUnimplemented>),
}

/// Enum for every kind of public subkeys, each variant being a combination of
/// a certain version and algorithm.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum PublicSubkey {
    Version4RsaEncryptSign(PublicVersion4<Subkey, RsaEncryptSign>),
    Version4Ecdh(PublicVersion4<Subkey, Ecdh>),
    Version4EdDsaLegacy(PublicVersion4<Subkey, EdDsaLegacy>),
    Version4X25519(PublicVersion4<Subkey, X25519>),
    Version4Ed25519(PublicVersion4<Subkey, Ed25519>),
    Version4Unimplemented(PublicVersion4<Subkey, PublicKeyAlgorithmUnimplemented>),
}

/// The public part of a version 4 key or subkey.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
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
    pub(crate) version: Span<()>,

    pub creation_time: Span<Time>,

    #[serde(serialize_with = "PublicVersion4::<R, A>::serialize_algorithm")]
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
    type SignatureMpis: SignatureMpis;
}

macro_rules! gen_public_key_algorithm_impls {
    ( $algorithm:ident, $mpis:ident ) => {
        impl PublicKeyAlgorithm for $algorithm {
            const ID: PublicKeyAlgorithmId = PublicKeyAlgorithmId::$algorithm;
            type SignatureMpis = $mpis;
        }
    };

    [ $( $algorithm:ident, $mpis:ident ),+ $(,)? ] => {
        $( gen_public_key_algorithm_impls!($algorithm, $mpis); )+
    };
}

macro_rules! gen_public_key_algorithm_id_enum {
    { $( $algorithm:ident = $algorithm_id:literal ),+ $(,)? } => {
        /// Every possible ID of public key algorithms as defined by [RFC 9580].
        ///
        /// [RFC 9580]: https://datatracker.ietf.org/doc/html/rfc9580#section-9.1
        #[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize_repr, TryFrom)]
        #[try_from(repr)]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum PublicKeyAlgorithmId {
            $( $algorithm = $algorithm_id ),+
        }
    };
}

macro_rules! gen_public_key_algorithm_enums_and_impls {
    { $( $algorithm:ident @ $mpis:ident = $algorithm_id:literal ),+ $(,)? } => {
        gen_public_key_algorithm_impls![$( $algorithm, $mpis ),+];

        gen_public_key_algorithm_id_enum! {
            $( $algorithm = $algorithm_id ),+
        }
    };
}

gen_public_key_algorithm_enums_and_impls! {
    RsaEncryptSign @ SignatureMpisRsa = 1,
    Ecdh @ SignatureMpisNever = 18,
    EdDsaLegacy @ SignatureMpisRS = 22,
    X25519 @ SignatureMpisNever = 25,
    Ed25519 @ SignatureMpisEd25519 = 27,
    PublicKeyAlgorithmUnimplemented @ SignatureMpisUnimplemented = 100,
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display("ECDH public key algorithm")]
pub struct Ecdh {
    pub curve_oid: Span<CurveOid>,
    pub q: Span<Mpi>,
    pub kdf_parameters: Span<KdfParameters>,
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display("EdDSALegacy (deprecated)")]
pub struct EdDsaLegacy {
    // Should always be the one representing Ed25519Legacy.
    pub curve_oid: Span<CurveOid>,
    // Should be prefixed with `0x40` but we don't need to worry about that.
    pub q: Span<Mpi>,
}

impl EdDsaLegacy {
    pub fn new(curve_oid: Span<CurveOid>, q: Span<Mpi>) -> Self {
        Self { curve_oid, q }
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[display("X25519")]
pub struct X25519(pub Span<[u8; 32]>);

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[display("Ed25519")]
pub struct Ed25519(pub Span<[u8; 32]>);

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[display("Unimplemented")]
pub struct PublicKeyAlgorithmUnimplemented;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Time(pub u32);

impl Time {
    pub fn new(secs_since_epoch: u32) -> Self {
        Self(secs_since_epoch)
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum Fingerprint {
    Version3(FingerprintVersion3),
    Version4(FingerprintVersion4),
    Version6(FingerprintVersion6),
}

impl Fingerprint {
    pub const VERSION_3_LEN: usize = 16;
    pub const VERSION_4_LEN: usize = 20;
    pub const VERSION_6_LEN: usize = 32;
}

impl Fingerprint {
    pub const fn version(&self) -> u8 {
        match self {
            Self::Version3(_) => 3,
            Self::Version4(_) => 4,
            Self::Version6(_) => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FingerprintVersion3(pub [u8; Fingerprint::VERSION_3_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FingerprintVersion4(pub [u8; Fingerprint::VERSION_4_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FingerprintVersion6(pub [u8; Fingerprint::VERSION_6_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KeyId(pub [u8; 8]);

macro_rules! gen_octets_display {
    { $( $octets:ty ),* $(,)? } => {
        $(
            impl Display for $octets {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    for octet in self.0 {
                        write!(f, "{:02X}", octet)?;
                    }
                    Ok(())
                }
            }
        )*
    };
}

gen_octets_display! {
    FingerprintVersion3,
    FingerprintVersion4,
    FingerprintVersion6,
    KeyId,
}

/// A representation of curve OID containing both its length and the actual OID.
///
/// This could have been implemented as (curve name omitted):
///
/// ```
/// pub struct CurveOid<const L: u8> {
///     pub length: Span<()>,
///     pub oid: Span<[u8; L as usize]>,
/// }
/// ```
///
/// ..., and the `oid` could also be an enum. However, that would unnecessarily
/// increase the implementation's complexity, and requires the unstable feature
/// `generic_const_exprs`. So we are using this less-constant implementaion
/// instead.
#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display("{}", name)]
pub struct CurveOid {
    pub name: CurveName,
    pub length: Span<u8>,
    pub oid: Span<Vec<u8>>,
}

impl CurveOid {
    pub fn new(name: CurveName, length: Span<u8>, oid: Span<Vec<u8>>) -> Self {
        Self { name, length, oid }
    }
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize)]
pub enum CurveName {
    #[display("NIST P-256")]
    NistP256,
    #[display("NIST P-384")]
    NistP384,
    #[display("NIST P-521")]
    NistP521,
    #[display("brainpoolP256r1")]
    BrainpoolP256R1,
    #[display("brainpoolP384r1")]
    BrainpoolP384R1,
    #[display("brainpoolP512r1")]
    BrainpoolP512R1,
    #[display("Ed25519Legacy")]
    Ed25519Legacy,
    #[display("Curve25519Legacy")]
    Curve25519Legacy,
}

/// Key derivation function (KDF) parameters.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KdfParameters {
    /// Placeholder representing the length of all fields that follow.
    ///
    /// For the actual value, see [`Self::LENGTH`].
    pub length: Span<PhantomData<u8>>,

    /// Placeholder for a reserved field.
    ///
    /// For the actual value, see [`Self::RESERVED`].
    pub reserved: Span<PhantomData<u8>>,

    pub hash_id: Span<HashAlgorithmId>,
    pub symmetric_id: Span<SymmetricKeyAlgorithmId>,
}

impl KdfParameters {
    pub const LENGTH: u8 = 3;
    pub const RESERVED: u8 = 1;
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum SymmetricKeyAlgorithmId {
    #[display("Plaintext or unencrypted data")]
    Plaintext = 0,
    #[display("IDEA")]
    Idea = 1,
    #[display("TripleDES (or DES-EDE) with 168-bit key derived from 192")]
    TripleDes = 2,
    #[display("CAST5 with 128-bit key")]
    Cast5 = 3,
    #[display("Blowfish with 128-bit key, 16 rounds")]
    Blowfish = 4,
    #[display("Reserved")]
    Reserved005 = 5,
    #[display("Reserved")]
    Reserved006 = 6,
    #[display("AES with 128-bit key")]
    Aes128 = 7,
    #[display("AES with 192-bit key")]
    Aes192 = 8,
    #[display("AES with 256-bit key")]
    Aes256 = 9,
    #[display("Twofish with 256-bit key")]
    Twofish = 10,
    #[display("Camellia with 128-bit key")]
    Camellia128 = 11,
    #[display("Camellia with 192-bit key")]
    Camellia192 = 12,
    #[display("Camellia with 256-bit key")]
    Camellia256 = 13,
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum CompressionAlgorithmId {
    Uncompressed = 0,

    #[display("ZIP")]
    Zip = 1,

    #[display("ZLIB")]
    Zlib = 2,

    BZip2 = 3,
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum HashAlgorithmId {
    #[display("MD5")]
    Md5 = 1,
    #[display("SHA-1")]
    Sha1 = 2,
    #[display("RIPEMD-160")]
    Ripemd160 = 3,
    #[display("SHA2-256")]
    Sha2_256 = 8,
    #[display("SHA2-384")]
    Sha2_384 = 9,
    #[display("SHA2-512")]
    Sha2_512 = 10,
    #[display("SHA2-224")]
    Sha2_224 = 11,
    #[display("SHA3-256")]
    Sha3_256 = 12,
    #[display("SHA3-512")]
    Sha3_512 = 14,
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, Serialize, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum AeadAlgorithmId {
    #[display("EAX")]
    Eax = 1,
    #[display("OCB")]
    Ocb = 2,
    #[display("GCM")]
    Gcm = 3,
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Serialize)]
#[display("[{}] User ID: {}", Self::TYPE_ID, self.user_id.inner)]
pub struct UserId {
    pub user_id: Span<String>,
}

impl UserId {
    pub fn new(user_id: Span<String>) -> Self {
        Self { user_id }
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
#[display("[{}] Reserved", Self::TYPE_ID)]
pub struct Reserved;

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize)]
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

        any_packet_unimplemented {
            AnyPacket::Unimplemented
        } => "Unimplemented"

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

        ecdh {
            Ecdh {
                curve_oid: dummy_span!(
                    CurveOid {
                        name: CurveName::Curve25519Legacy,
                        length: dummy_span!(0),
                        oid: dummy_span!(vec![]),
                    }
                ),
                q: dummy_span!(dummy_mpi!()),
                kdf_parameters: dummy_span!(
                    KdfParameters {
                        length: dummy_span!(PhantomData),
                        reserved: dummy_span!(PhantomData),
                        hash_id: dummy_span!(HashAlgorithmId::Sha2_256),
                        symmetric_id: dummy_span!(SymmetricKeyAlgorithmId::Aes128),
                    }
                )
            }
        } => "ECDH public key algorithm"

        eddsa_legacy {
            EdDsaLegacy {
                curve_oid: dummy_span!(
                    CurveOid {
                        name: CurveName::Ed25519Legacy,
                        length: dummy_span!(0),
                        oid: dummy_span!(vec![]),
                    }
                ),
                q: dummy_span!(dummy_mpi!()),
            }
        } => "EdDSALegacy (deprecated)"

        x25519 {
            X25519(dummy_span!([0; 32]))
        } => "X25519"

        ed25519 {
            Ed25519(dummy_span!([0; 32]))
        } => "Ed25519"

        unimplemented_public_key_algorithm {
            PublicKeyAlgorithmUnimplemented
        } => "Unimplemented"

        curve_oid {
            CurveOid {
                name: CurveName::Curve25519Legacy,
                length: dummy_span!(0),
                oid: dummy_span!(vec![]),
            }
        } => "Curve25519Legacy"

        // Not testing exhaustively.
        curve_name_curve25519_legacy {
            CurveName::Curve25519Legacy
        } => "Curve25519Legacy"

        // Not testing exhaustively.
        symmetric_key_algorithm_id {
            SymmetricKeyAlgorithmId::Plaintext
        } => "Plaintext or unencrypted data"

        // Not testing exhaustively.
        hash_algorithm_id {
            HashAlgorithmId::Md5
        } => "MD5"

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
