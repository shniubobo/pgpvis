//! `Result`- and `Error`-related types for the crate.

use std::result::Result as StdResult;

use sequoia_openpgp as pgp;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error has been returned from [`sequoia_openpgp`].
    ///
    /// [`sequoia_openpgp`] currently returns [`anyhow::Error`], which is [bad
    /// practice and planned to be changed]. As a result, we have to also
    /// depend on [`anyhow::Error`].
    ///
    /// [bad practice and planned to be changed]:
    ///     https://gitlab.com/sequoia-pgp/sequoia/-/issues/1020
    #[error("failed to parse packet")]
    Parse(#[from] anyhow::Error),

    // TODO: Remove this after we've implemented all packet types.
    #[error("unimplemented packet; type id: {type_id}")]
    UnknownPacket { type_id: u8 },

    // This should not occur as long as we define packet fields correctly,
    // but just in case we do it wrong, we can return this instead of
    // panicking.
    #[error("span {field} not found on packet type: {tag}")]
    SpanNotFound { field: usize, tag: pgp::packet::Tag },
}
