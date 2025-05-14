//! `Result`- and `Error`-related types for the crate.

use std::result::Result as StdResult;
use std::{array::TryFromSliceError, num::TryFromIntError};

use enumflags2::FromBitsError;
use sequoia_openpgp::{self as pgp, anyhow::Error as PgpError};

use crate::packet::*;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid bitflags: {}", .0)]
    InvalidBitflags(#[from] BitflagsError),

    #[error("invalid key ID")]
    InvalidKeyId,

    // This should never be created, as long as `sequoia_openpgp` is
    // functioning correctly.
    #[error("{bits} bits cannot be represented with two octets")]
    MpiLengthOverflow { bits: usize },

    // TODO: Replace the other overflow variants with this.
    #[error("an overflow occurred during int conversion")]
    Overflow(#[from] TryFromIntError),

    /// An error has been returned from [`sequoia_openpgp`].
    ///
    /// [`sequoia_openpgp`] currently returns `anyhow::Error`, which is [bad
    /// practice and planned to be changed]. As a result, we have to also
    /// depend on `anyhow::Error`.
    ///
    /// Update: [`sequoia_openpgp`] since v2.0.0 re-exports `anyhow::Error` as
    /// [`sequoia_openpgp::anyhow::Error`], so we are saved from depending
    /// *directly* on `anyhow`. However, dependency on `anyhow` is still
    /// necessary until we see [`sequoia_openpgp`] reach v3. See also the
    /// linked issue.
    ///
    /// [bad practice and planned to be changed]:
    ///     https://gitlab.com/sequoia-pgp/sequoia/-/issues/1020
    #[error("failed to parse packet")]
    Parse(#[from] PgpError),

    #[error("failed to read message")]
    Read(#[from] std::io::Error),

    // This should not occur as long as we define packet fields correctly,
    // but just in case we do it wrong, we can return this instead of
    // panicking.
    #[error("span {field} not found")]
    SpanNotFound { field: usize },

    #[error("a subpacket area length cannot be {length}, which exceeds two octets")]
    SubpacketAreaLengthOverflow { length: usize },

    // This should never be created, as long as `sequoia_openpgp` is
    // functioning correctly.
    #[error("{secs} seconds cannot be represented with four octets")]
    TimeOverflow { secs: u64 },

    // TODO: Remove this after it's no longer needed, i.e., when everything
    // gets implemented.
    /// An error returned when something is not yet implemented, but it's not
    /// feasible to call [`unimplemented!`].
    #[error("not yet implemented: {}", .0)]
    Unimplemented(String),

    // TODO: Remove this after we've implemented all packet types.
    #[error("unimplemented packet at span {span}; type id: {type_id}")]
    UnimplementedPacket { type_id: u8, span: Span<()> },

    #[error("wrong length of bitflags")]
    WrongBitflagsLength(#[from] TryFromSliceError),

    #[error("wrong length of a version {version} fingerprint: {length}")]
    WrongFingerprintLength { version: u8, length: usize },

    #[error("expected fingerprint version {expected}, got {got}")]
    WrongFingerprintVersion { expected: u8, got: u8 },

    // The plan is that we allow conversion between the two formats in the
    // future, and this `Error` is returned in case a `CTB` of the wrong format
    // has been passed in. This won't be useful if we decide not to implement
    // the conversion, in which case we can return an `Option`, just panic,
    // or preferably redesign the types so that it's impossible for a wrong
    // type to be passed in.
    #[error("expected CTB format {expected}, got {got}")]
    WrongFormat { expected: String, got: String },

    #[error("expected public key algorithm {expected}, got {got}")]
    WrongPublicKeyAlgorithm {
        expected: PublicKeyAlgorithmId,
        got: pgp::types::PublicKeyAlgorithm,
    },

    // It is impossible to have a trait object of `SignatureMpis` here, as its
    // supertrait `Serialize` is not dyn-compatible. It is also impossible to
    // convert from `pgp::crypto::mpi::Signature` into a `Display` string, and
    // a `Debug` string needs to be instead constructed beforehand.
    #[error("expected mpis {expected}, got {got}")]
    WrongSignatureMpis { expected: &'static str, got: String },

    #[error("wrong first octet of {length}-octet signature subpacket length: {first}")]
    WrongSignatureSubpacketLengthEncoding { length: u8, first: u8 },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BitflagsError {
    #[error("failed to convert to notation data bitflags")]
    NotationData(#[from] FromBitsError<NotationDataFlag>),

    #[error("failed to convert to key server preferences bitflags octet 0")]
    KeyServerPreferences0(#[from] FromBitsError<KeyServerPreferencesFlags0>),

    #[error("failed to convert to key flags bitflags octet 0")]
    KeyFlags0(#[from] FromBitsError<KeyFlagsFlags0>),

    #[error("failed to convert to key flags bitflags octet 1")]
    KeyFlags1(#[from] FromBitsError<KeyFlagsFlags1>),

    #[error("failed to convert to features bitflags octet 0")]
    Features0(#[from] FromBitsError<FeaturesFlags0>),
}
