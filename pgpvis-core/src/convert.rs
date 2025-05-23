//! Utility structs to convert from [`sequoia_openpgp`]'s data structures into
//! our own ones in [`packet`](crate::packet).

use std::marker::PhantomData;
use std::result::Result as StdResult;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sequoia_openpgp::{self as pgp, packet::key as pgp_key, parse::PacketParser};

use crate::error::*;
use crate::packet::*;

/// Converts [`PacketParser`] into [`Span<AnyPacket>`].
pub(crate) struct Converter<'context> {
    context: &'context mut Context,
    field_lengths: Vec<usize>,
    next_field_index: usize,
}

impl<'c> Converter<'c> {
    /// Constructs a new [`Converter`].
    ///
    /// - `context`: A [`Context`] shared by multiple [`Converter`]s, so as to
    ///   keep track of the parsing states.
    /// - `field_lengths`: A [`Vec`] containing the length of each packet field,
    ///   retrieved by calling [`Converter::field_lengths`].
    // We ask for `field_lengths` here instead of a `&PacketParser`, so that we
    // don't need to mock the parser for testing.
    pub fn new(context: &'c mut Context, field_lengths: Vec<usize>) -> Converter<'c> {
        Self {
            context,
            field_lengths,
            next_field_index: 0,
        }
    }

    /// Acquire the length of each field, which is required by [`Converter::new`].
    ///
    /// Mapping must be enabled on the [`PacketParser`].
    pub fn field_lengths(parser: &PacketParser) -> Vec<usize> {
        parser
            .map()
            .expect("mapping must be enabled on the parser")
            .iter()
            .map(|field| field.as_bytes().len())
            .collect()
    }

    // Although we only need a mutable reference to `self` instead of ownership,
    // requiring the latter prevents `convert` from being called for multiple
    // times on the same `Converter`. This is intended, mainly because it doesn't
    // make sense to call `convert` multiple times with different `parser`s, since
    // they don't share the same `field_lengths`. Another reason is that
    // `next_field_index` is not reset to 0 after each call, though this one is
    // not as significant as the previous, and can be solved by simply resetting
    // the field.
    pub fn convert(mut self, parser: &PacketParser) -> Result<Span<AnyPacket>> {
        AnyPacket::convert_spanned(parser, &mut self)
    }
}

impl Converter<'_> {
    /// Return the next span, as indicated by [`next_field_index`](Self::next_field_index),
    /// without an inner value.
    fn next_span(&mut self) -> Result<Span<()>> {
        self.next_span_with(())
    }

    /// Return the next span, as indicated by [`next_field_index`](Self::next_field_index),
    /// with the inner value being `inner`.
    fn next_span_with<T>(&mut self, inner: T) -> Result<Span<T>> {
        let field = self.next_field_index();
        let (offset, length) = self.advance_offset(field)?;
        Ok(Span::new(offset, length, inner))
    }

    /// Return the next field index, and advance the index.
    fn next_field_index(&mut self) -> usize {
        let index = self.next_field_index;
        self.next_field_index += 1;
        index
    }

    /// Record the span length advanced by `closure`.
    fn spanned<T>(&mut self, closure: impl FnOnce(&mut Self) -> Result<T>) -> Result<Span<T>> {
        self.spanned_with(&(), |_, converter| closure(converter))
    }

    /// Record the span length advanced by `closure`, passing `value` to `closure`.
    fn spanned_with<V, T>(
        &mut self,
        value: &V,
        closure: impl FnOnce(&V, &mut Self) -> Result<T>,
    ) -> Result<Span<T>> {
        let offset = self.offset();
        let inner = closure(value, self)?;
        let length = self.offset() - offset;
        Ok(Span::new(offset, length, inner))
    }

    /// The current offset as recorded by [`context`](Self::context).
    fn offset(&self) -> usize {
        self.context.offset()
    }

    /// Advance the offset as recorded by [`context`](Self::context), by the
    /// length of the `field`-th field, returning the offset and length of that
    /// field, which is useful for the creation of a [`Span`].
    fn advance_offset(&mut self, field: usize) -> Result<(usize, usize)> {
        let field_length = *self
            .field_lengths
            .get(field)
            .ok_or(Error::SpanNotFound { field })?;
        let offset = self.context.offset();
        self.context.advance_offset(field_length);

        Ok((offset, field_length))
    }
}

/// Records the state of parsing.
pub(crate) struct Context {
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

/// Implemented by types in [`packet`](crate::packet), so that they can be
/// converted from types in [`sequoia_openpgp`].
///
/// [`convert_spanned`](Convert::convert_spanned) is a provided method, but
/// the implmentation may override it if the [`Span`] should not be
/// automatically recorded, in which case [`convert`](Convert::convert) should
/// be [`unreachable!`].
///
/// Callers should always call [`convert_spanned`](Convert::convert_spanned),
/// and never [`convert`](Convert::convert).
trait Convert<F> {
    /// Convert and record the span length advanced during conversion.
    fn convert_spanned(from: &F, converter: &mut Converter) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        converter.spanned_with(from, Self::convert)
    }

    fn convert(from: &F, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized;
}

macro_rules! convert_packet {
    ($header:ident, $body:ident, $converter:ident) => {
        Packet {
            header: Header::convert_spanned($header, $converter)?,
            body: Body::convert_spanned($body, $converter)?,
        }
    };
}

impl Convert<PacketParser<'_>> for AnyPacket {
    fn convert(from: &PacketParser, converter: &mut Converter) -> Result<Self> {
        let header = from.header();
        let body = &from.packet;
        let ret = match body {
            pgp::Packet::PublicKey(body) => {
                AnyPacket::PublicKey(convert_packet!(header, body, converter))
            }
            pgp::Packet::UserID(body) => {
                AnyPacket::UserId(convert_packet!(header, body, converter))
            }
            pgp::Packet::PublicSubkey(body) => {
                AnyPacket::PublicSubkey(convert_packet!(header, body, converter))
            }
            unknown_packet => {
                let span = converter.spanned(|converter| {
                    // Drain all spans, so that `spanned` record their total length.
                    while converter.next_span().is_ok() {}
                    Ok(())
                })?;
                return Err(Error::UnimplementedPacket {
                    type_id: unknown_packet.tag().into(),
                    span,
                });
            }
        };
        Ok(ret)
    }
}

impl<T> Convert<pgp::packet::Header> for Header<T>
where
    T: PacketType,
{
    fn convert(from: &pgp::packet::Header, converter: &mut Converter) -> Result<Self> {
        let ctb = from.ctb();
        let ret = match ctb {
            pgp::packet::header::CTB::New(_) => Header::OpenPgp {
                ctb: OpenPgpCtb::convert_spanned(ctb, converter)?,
                length: OpenPgpLength::convert_spanned(from, converter)?,
            },
            pgp::packet::header::CTB::Old(_) => Header::Legacy {
                ctb: LegacyCtb::convert_spanned(ctb, converter)?,
                length: LegacyLength::convert_spanned(from, converter)?,
            },
        };
        Ok(ret)
    }
}

impl<T> Convert<pgp::packet::header::CTB> for OpenPgpCtb<T>
where
    T: PacketType,
{
    fn convert_spanned(
        from: &pgp::packet::header::CTB,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        let ctb = Self::from_openpgp(from)
            .or_else(|_| Self::from_legacy(from))
            .unwrap();
        converter.next_span_with(ctb)
    }

    fn convert(_from: &pgp::packet::header::CTB, _converter: &mut Converter) -> Result<Self> {
        unreachable!()
    }
}

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

    pub fn from_legacy(_ctb: &pgp::packet::header::CTB) -> Result<Self> {
        Err(Error::Unimplemented("OpenPgpCtb::from_legacy".to_string()))
    }
}

impl<T> Convert<pgp::packet::header::CTB> for LegacyCtb<T>
where
    T: PacketType,
{
    fn convert_spanned(
        from: &pgp::packet::header::CTB,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        let ctb = Self::from_openpgp(from)
            .or_else(|_| Self::from_legacy(from))
            .unwrap();
        converter.next_span_with(ctb)
    }

    fn convert(_from: &pgp::packet::header::CTB, _converter: &mut Converter) -> Result<Self> {
        unreachable!()
    }
}

impl<T> LegacyCtb<T>
where
    T: PacketType,
{
    pub fn from_openpgp(_ctb: &pgp::packet::header::CTB) -> Result<Self> {
        Err(Error::Unimplemented("LegacyCtb::from_openpgp".to_string()))
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

impl Convert<pgp::packet::Header> for OpenPgpLength {
    fn convert_spanned(
        from: &pgp::packet::Header,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        if let pgp::packet::header::CTB::Old(_) = from.ctb() {
            return Err(Error::WrongFormat {
                expected: "OpenPGP".to_string(),
                got: "Legacy".to_string(),
            });
        };

        use pgp::packet::header::BodyLength as PgpBodyLength;
        let length = match *from.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(length) => Self::Partial(length),
            PgpBodyLength::Indeterminate => unreachable!(),
        };
        converter.next_span_with(length)
    }

    fn convert(_from: &pgp::packet::Header, _converter: &mut Converter) -> Result<Self> {
        unreachable!()
    }
}

impl Convert<pgp::packet::Header> for LegacyLength {
    fn convert_spanned(
        from: &pgp::packet::Header,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        if let pgp::packet::header::CTB::New(_) = from.ctb() {
            return Err(Error::WrongFormat {
                expected: "Legacy".to_string(),
                got: "OpenPGP".to_string(),
            });
        };

        use pgp::packet::header::BodyLength as PgpBodyLength;
        let length = match *from.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(_) => unreachable!(),
            PgpBodyLength::Indeterminate => Self::Indeterminate,
        };
        converter.next_span_with(length)
    }

    fn convert(_from: &pgp::packet::Header, _converter: &mut Converter) -> Result<Self> {
        unreachable!()
    }
}

impl<F, T> Convert<F> for Body<T>
where
    T: PacketType + Convert<F>,
{
    fn convert_spanned(from: &F, converter: &mut Converter) -> Result<Span<Self>> {
        Ok(T::convert_spanned(from, converter)?.transpose())
    }

    fn convert(_from: &F, _converter: &mut Converter) -> Result<Self> {
        unreachable!()
    }
}

macro_rules! convert_key {
    { $conversion:tt } => {
        impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>> for PublicKey {
            fn convert(
                from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>,
                converter: &mut Converter,
            ) -> Result<Self> {
                convert_key! { from, converter $conversion }
            }
        }

        impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>>
            for PublicSubkey
        {
            fn convert(
                from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>,
                converter: &mut Converter,
            ) -> Result<Self> {
                convert_key! { from, converter $conversion }
            }
        }
    };

    {
        $from:ident, $converter:ident {
            $($from_inner:ident => $to:ident ( $to_inner:ty ) );+ $(;)?
        }
    } => {
        if let pgp::packet::Key::V4(key) = $from {
            let version_span = $converter.next_span()?;
            let creation_time = Time::convert_spanned($from, $converter)?;
            let algorithm_span = $converter.next_span()?;
            let key_id = $from.keyid().to_hex();
            let ret = match key.pk_algo() {
                $(
                    pgp::types::PublicKeyAlgorithm::$from_inner => {
                        let key_material = <$to_inner>::convert_spanned($from.mpis(), $converter)?;
                        Self::$to(PublicVersion4::new(
                            version_span,
                            creation_time,
                            algorithm_span,
                            key_material,
                            key_id,
                        ))
                    }
                )+
                _ => {
                    let key_material = $converter.spanned(|converter| {
                        // Exhaust all remaining spans.
                        while let Ok(_) = converter.next_span() {}
                        Ok(UnimplementedPublicKeyAlgorithm)
                    })?;
                    Self::Version4Unimplemented(
                        PublicVersion4::new(
                            version_span,
                            creation_time,
                            algorithm_span,
                            key_material,
                            key_id,
                        )
                    )
                },
            };
            return Ok(ret);
        };
        Err(Error::Unimplemented(format!("version {}", $from.version())))
    };
}

convert_key! {{
    RSAEncryptSign => Version4RsaEncryptSign(RsaEncryptSign);
    ECDH => Version4Ecdh(Ecdh);
    EdDSA => Version4EdDsaLegacy(EdDsaLegacy);
    X25519 => Version4X25519(X25519);
    Ed25519 => Version4Ed25519(Ed25519);
}}

impl<R> Convert<pgp::packet::Key<pgp_key::PublicParts, R>> for Time
where
    R: pgp_key::KeyRole,
{
    fn convert_spanned(
        from: &pgp::packet::Key<pgp_key::PublicParts, R>,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        let creation_time = from.creation_time().try_into()?;
        let span = converter.next_span_with(creation_time)?;
        Ok(span)
    }

    fn convert(
        _from: &pgp::packet::Key<pgp_key::PublicParts, R>,
        _converter: &mut Converter,
    ) -> Result<Self> {
        unreachable!()
    }
}

impl TryFrom<SystemTime> for Time {
    type Error = Error;

    fn try_from(time: SystemTime) -> StdResult<Self, Self::Error> {
        let since_epoch = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
        if since_epoch > u32::MAX.into() {
            return Err(Error::TimeOverflow { secs: since_epoch });
        }
        Ok(Self::new(since_epoch as u32))
    }
}

macro_rules! err_wrong_algorithm {
    ( $from:ident ) => {
        Err(Error::WrongPublicKeyAlgorithm {
            expected: Self::ID,
            got: $from
                .algo()
                // Returning 0 since we cannot get the exact id here.
                .unwrap_or(pgp::types::PublicKeyAlgorithm::Unknown(0)),
        })
    };
}

impl Convert<pgp::crypto::mpi::PublicKey> for RsaEncryptSign {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::RSA { e, n } = from {
            let n = Mpi::convert_spanned(n, converter)?;
            let e = Mpi::convert_spanned(e, converter)?;
            return Ok(RsaEncryptSign::new(n, e));
        }

        err_wrong_algorithm!(from)
    }
}

impl Convert<pgp::crypto::mpi::PublicKey> for Ecdh {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::ECDH {
            curve,
            q,
            hash,
            sym,
        } = from
        {
            let curve_oid = CurveOid::convert_spanned(curve, converter)?;
            let q = Mpi::convert_spanned(q, converter)?;
            let kdf_parameters = KdfParameters::convert_spanned(&(hash, sym), converter)?;
            return Ok(Self {
                curve_oid,
                q,
                kdf_parameters,
            });
        }

        err_wrong_algorithm!(from)
    }
}

impl Convert<pgp::crypto::mpi::PublicKey> for EdDsaLegacy {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::EdDSA { curve, q } = from {
            let curve_oid = CurveOid::convert_spanned(curve, converter)?;
            let q = Mpi::convert_spanned(q, converter)?;
            return Ok(Self::new(curve_oid, q));
        }

        err_wrong_algorithm!(from)
    }
}

impl Convert<pgp::crypto::mpi::PublicKey> for X25519 {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::X25519 { u } = from {
            return Ok(X25519(converter.next_span_with(*u)?));
        }

        err_wrong_algorithm!(from)
    }
}

impl Convert<pgp::crypto::mpi::PublicKey> for Ed25519 {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::Ed25519 { a } = from {
            return Ok(Ed25519(converter.next_span_with(*a)?));
        }

        err_wrong_algorithm!(from)
    }
}

impl Convert<pgp::crypto::mpi::MPI> for Mpi {
    fn convert(from: &pgp::crypto::mpi::MPI, converter: &mut Converter) -> Result<Self> {
        let length_field = from.bits();
        if length_field > u16::MAX.into() {
            return Err(Error::MpiLengthOverflow { bits: length_field });
        }
        let length_field_span = converter.next_span_with(length_field as u16)?;
        let integers_span = converter.next_span_with(from.value().to_vec())?;
        Ok(Mpi::new(length_field_span, integers_span))
    }
}

impl Convert<pgp::crypto::Curve> for CurveOid {
    fn convert(from: &pgp::crypto::Curve, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(CurveOid::new(
            from.try_into()?,
            // This cast should be okay, as long as sequoia-openpgp is not
            // mal-functioning.
            //
            // TODO: Add an overflow check as we have done for `Mpi` and `Time`.
            converter.next_span_with(from.oid().len() as u8)?,
            converter.next_span_with(from.oid().to_vec())?,
        ))
    }
}

impl TryFrom<&pgp::crypto::Curve> for CurveName {
    type Error = Error;

    fn try_from(value: &pgp::crypto::Curve) -> StdResult<Self, Self::Error> {
        Ok(match value {
            pgp::types::Curve::NistP256 => Self::NistP256,
            pgp::types::Curve::NistP384 => Self::NistP384,
            pgp::types::Curve::NistP521 => Self::NistP521,
            pgp::types::Curve::BrainpoolP256 => Self::BrainpoolP256R1,
            pgp::types::Curve::BrainpoolP384 => Self::BrainpoolP384R1,
            pgp::types::Curve::BrainpoolP512 => Self::BrainpoolP512R1,
            pgp::types::Curve::Ed25519 => Self::Ed25519Legacy,
            pgp::types::Curve::Cv25519 => Self::Curve25519Legacy,
            curve => return Err(Self::Error::Unimplemented(curve.to_string())),
        })
    }
}

impl
    Convert<(
        &pgp::crypto::HashAlgorithm,
        &pgp::crypto::SymmetricAlgorithm,
    )> for KdfParameters
{
    fn convert(
        from: &(
            &pgp::crypto::HashAlgorithm,
            &pgp::crypto::SymmetricAlgorithm,
        ),
        converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let (hash_id, symmetric_id) = from;
        let length = converter.next_span_with(PhantomData)?;
        let reserved = converter.next_span_with(PhantomData)?;
        let hash_id = HashAlgorithmId::convert_spanned(hash_id, converter)?;
        let symmetric_id = SymmetricKeyAlgorithmId::convert_spanned(symmetric_id, converter)?;
        Ok(Self {
            length,
            reserved,
            hash_id,
            symmetric_id,
        })
    }
}

impl Convert<pgp::crypto::SymmetricAlgorithm> for SymmetricKeyAlgorithmId {
    fn convert_spanned(
        from: &pgp::crypto::SymmetricAlgorithm,
        converter: &mut Converter,
    ) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        converter.next_span_with(match from {
            pgp::crypto::SymmetricAlgorithm::Unencrypted => Self::Plaintext,
            #[expect(deprecated)]
            pgp::crypto::SymmetricAlgorithm::IDEA => Self::Idea,
            #[expect(deprecated)]
            pgp::crypto::SymmetricAlgorithm::TripleDES => Self::TripleDes,
            #[expect(deprecated)]
            pgp::crypto::SymmetricAlgorithm::CAST5 => Self::Cast5,
            pgp::crypto::SymmetricAlgorithm::Blowfish => Self::Blowfish,
            pgp::crypto::SymmetricAlgorithm::AES128 => Self::Aes128,
            pgp::crypto::SymmetricAlgorithm::AES192 => Self::Aes192,
            pgp::crypto::SymmetricAlgorithm::AES256 => Self::Aes256,
            pgp::crypto::SymmetricAlgorithm::Twofish => Self::Twofish,
            pgp::crypto::SymmetricAlgorithm::Camellia128 => Self::Camellia128,
            pgp::crypto::SymmetricAlgorithm::Camellia192 => Self::Camellia192,
            pgp::crypto::SymmetricAlgorithm::Camellia256 => Self::Camellia256,
            _ => {
                let symmetric_id: u8 = (*from).into();
                return Err(Error::Unimplemented(format!(
                    "symmetric algorithm id: {}",
                    symmetric_id
                )));
            }
        })
    }

    fn convert(_from: &pgp::crypto::SymmetricAlgorithm, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl Convert<pgp::crypto::HashAlgorithm> for HashAlgorithmId {
    fn convert_spanned(
        from: &pgp::crypto::HashAlgorithm,
        converter: &mut Converter,
    ) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        converter.next_span_with(match from {
            pgp::crypto::HashAlgorithm::MD5 => Self::Md5,
            pgp::crypto::HashAlgorithm::SHA1 => Self::Sha1,
            pgp::crypto::HashAlgorithm::RipeMD => Self::Ripemd160,
            pgp::crypto::HashAlgorithm::SHA256 => Self::Sha2_256,
            pgp::crypto::HashAlgorithm::SHA384 => Self::Sha2_384,
            pgp::crypto::HashAlgorithm::SHA512 => Self::Sha2_512,
            pgp::crypto::HashAlgorithm::SHA224 => Self::Sha2_224,
            pgp::crypto::HashAlgorithm::SHA3_256 => Self::Sha3_256,
            pgp::crypto::HashAlgorithm::SHA3_512 => Self::Sha3_512,
            _ => {
                let hash_id: u8 = (*from).into();
                return Err(Error::Unimplemented(format!(
                    "hash algorithm id: {}",
                    hash_id
                )));
            }
        })
    }

    fn convert(_from: &pgp::crypto::HashAlgorithm, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl Convert<pgp::packet::UserID> for UserId {
    fn convert(from: &pgp::packet::UserID, converter: &mut Converter) -> Result<Self> {
        let user_id_field = String::from_utf8_lossy(from.value()).to_string();
        let span = converter.next_span_with(user_id_field)?;
        Ok(UserId::new(span))
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt::Display, time::Duration};

    use pgp::parse::Parse;
    use serde::Serialize;

    use super::*;

    /// Make an assertion using [`insta::assert_yaml_snapshot!`], saving snapshots
    /// in `{crate_root}/tests/snapshots`.
    macro_rules! insta_assert {
        ($value:ident) => {
            let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let snapshot_path = crate_root.join("tests/snapshots");
            insta::with_settings!({snapshot_path => snapshot_path}, {
                insta::assert_yaml_snapshot!($value);
            });
        };
    }

    /// Generate tests that each asserts
    /// 1. A given type (1) can be [`Convert`]ed from a certain value (2); and
    /// 2. The conversion consumes an exact number of fields (3).
    ///
    /// To call this macro:
    /// ```text
    /// assert_convert! {
    ///     [function name of test] {
    ///         [2] => [3] @ [1]
    ///     }
    ///
    ///     [repeat for other tests]
    /// }
    /// ```
    macro_rules! assert_convert {
        ({ $from:expr => $fields:literal @ $to:ty }) => {
            // Ensure exact number of fields.
            let mut context = Context::new();
            let mut converter = Converter::new(&mut context, vec![1; $fields - 1]);
            assert!(<$to>::convert_spanned(&$from, &mut converter).is_err());

            let mut context = Context::new();
            let mut converter = Converter::new(&mut context, vec![1; $fields]);
            let value = <$to>::convert_spanned(&$from, &mut converter).unwrap();
            insta_assert!(value);
        };

        {$( $fn_name:ident $conversion:tt )*} => {
            $(
                #[test]
                fn $fn_name() {
                    assert_convert!($conversion);
                }
            )*
        };
    }

    #[derive(Debug, Serialize)]
    struct DummyPacket;
    impl Display for DummyPacket {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "DummyPacket")
        }
    }
    impl PacketType for DummyPacket {
        const TYPE_ID: TypeId = TypeId::Private60;
    }
    impl Convert<()> for DummyPacket {
        fn convert(_: &(), converter: &mut Converter) -> Result<Self> {
            converter.next_span()?;
            Ok(Self)
        }
    }

    assert_convert! {
        // Not testing each variant here. That the correct variant is produced
        // needs to be checked with eyes (by looking at `AnyPacket`'s impl).
        any_packet {
            PacketParser::from_bytes(
                b"\xb4\x17John <john@example.com>"
            ).unwrap().unwrap()
                => 3 @ AnyPacket
        }

        header_openpgp {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::new(pgp::packet::Tag::Private(60)),
                pgp::packet::header::BodyLength::Full(0),
            ) => 2 @ Header<Private60>
        }

        header_legacy {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::Old(
                    pgp::packet::header::CTBOld::new(
                        pgp::packet::Tag::Reserved,
                        pgp::packet::header::BodyLength::Full(0),
                    ).unwrap(),
                ),
                pgp::packet::header::BodyLength::Full(0),
            ) => 2 @ Header<Reserved>
        }

        openpgp_ctb {
            pgp::packet::header::CTB::new(pgp::packet::Tag::Private(60))
                => 1 @ OpenPgpCtb<Private60>
        }

        legecy_ctb {
            pgp::packet::header::CTB::Old(
                pgp::packet::header::CTBOld::new(
                    pgp::packet::Tag::Reserved,
                    pgp::packet::header::BodyLength::Full(0),
                ).unwrap(),
            ) => 1 @ LegacyCtb<Reserved>
        }

        openpgp_length_full {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::new(pgp::packet::Tag::Private(60)),
                pgp::packet::header::BodyLength::Full(0),
            ) => 1 @ OpenPgpLength
        }

        openpgp_length_partial {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::new(pgp::packet::Tag::Private(60)),
                pgp::packet::header::BodyLength::Partial(0),
            ) => 1 @ OpenPgpLength
        }

        legacy_length_full {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::Old(
                    pgp::packet::header::CTBOld::new(
                        pgp::packet::Tag::Reserved,
                        pgp::packet::header::BodyLength::Full(0),
                    ).unwrap(),
                ),
                pgp::packet::header::BodyLength::Full(0),
            ) => 1 @ LegacyLength
        }

        legacy_length_indeterminate {
            pgp::packet::Header::new(
                pgp::packet::header::CTB::Old(
                    pgp::packet::header::CTBOld::new(
                        pgp::packet::Tag::Reserved,
                        pgp::packet::header::BodyLength::Full(0),
                    ).unwrap(),
                ),
                pgp::packet::header::BodyLength::Indeterminate,
            ) => 1 @ LegacyLength
        }

        body {
            () => 1 @ Body<DummyPacket>
        }

        // Each algorithm is tested in its own test.
        public_key_version_4 {
            pgp::packet::Key::V4(
                pgp::packet::key::Key4::<_, pgp::packet::key::PrimaryRole>::new(
                    SystemTime::UNIX_EPOCH,
                    pgp::types::PublicKeyAlgorithm::RSAEncryptSign,
                    pgp::crypto::mpi::PublicKey::RSA {
                        e: pgp::crypto::mpi::MPI::new(&[4]),
                        n: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                    },
                ).unwrap()
            ) => 7 @ PublicKey
        }

        // Since the code of subkeys is identical to that of keys, we are not
        // testing subkeys as thoroughly here.
        public_subkey {
            pgp::packet::Key::V4(
                pgp::packet::key::Key4::<_, pgp::packet::key::SubordinateRole>::new(
                    SystemTime::UNIX_EPOCH,
                    pgp::types::PublicKeyAlgorithm::RSAEncryptSign,
                    pgp::crypto::mpi::PublicKey::RSA {
                        e: pgp::crypto::mpi::MPI::new(&[4]),
                        n: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                    },
                ).unwrap()
            ) => 7 @ PublicSubkey
        }

        time {
            pgp::packet::Key::V4(
                pgp::packet::key::Key4::<_, pgp::packet::key::PrimaryRole>::new(
                    SystemTime::UNIX_EPOCH,
                    pgp::types::PublicKeyAlgorithm::RSAEncryptSign,
                    pgp::crypto::mpi::PublicKey::RSA {
                        e: pgp::crypto::mpi::MPI::new(&[4]),
                        n: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                    },
                ).unwrap()
            ) => 1 @ Time
        }

        rsa_encrypt_sign {
            pgp::crypto::mpi::PublicKey::RSA {
                e: pgp::crypto::mpi::MPI::new(&[4]),
                n: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
            } => 4 @ RsaEncryptSign
        }

        ecdh {
            pgp::crypto::mpi::PublicKey::ECDH {
                curve: pgp::crypto::Curve::Cv25519,
                q: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                hash: pgp::crypto::HashAlgorithm::SHA256,
                sym: pgp::crypto::SymmetricAlgorithm::AES128,
            } => 8 @ Ecdh
        }

        eddsa_legacy {
            pgp::crypto::mpi::PublicKey::EdDSA {
                curve: pgp::crypto::Curve::Ed25519,
                q: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
            } => 4 @ EdDsaLegacy
        }

        x25519 {
            pgp::crypto::mpi::PublicKey::X25519 {
                u: [0u8; 32],
            } => 1 @ X25519
        }

        ed25519 {
            pgp::crypto::mpi::PublicKey::Ed25519 {
                a: [0u8; 32],
            } => 1 @ Ed25519
        }

        mpi {
            pgp::crypto::mpi::MPI::new(&[1, 2, 3]) => 2 @ Mpi
        }

        curve_oid {
            pgp::crypto::Curve::Ed25519 => 2 @ CurveOid
        }

        kdf_parameters {
            (
                &pgp::crypto::HashAlgorithm::SHA256,
                &pgp::crypto::SymmetricAlgorithm::AES128,
            ) => 4 @ KdfParameters
        }

        symmetric_key_algorithm_id {
            pgp::crypto::SymmetricAlgorithm::Unencrypted => 1 @ SymmetricKeyAlgorithmId
        }

        hash_algorithm_id {
            pgp::crypto::HashAlgorithm::SHA512 => 1 @ HashAlgorithmId
        }

        user_id {
            pgp::packet::UserID::from_address(Some("John"), None, "john@example.com").unwrap()
                => 1 @ UserId
        }
    }

    #[test]
    fn public_key_version_4_unimplemented() {
        let mut context = Context::new();
        let mut converter = Converter::new(&mut context, vec![1; 11]);

        // Use DSA for this as we won't implement it anytime soon.
        let from = pgp::packet::Key::V4(
            pgp::packet::key::Key4::<_, pgp::packet::key::PrimaryRole>::new(
                SystemTime::UNIX_EPOCH,
                #[expect(deprecated)]
                pgp::types::PublicKeyAlgorithm::DSA,
                pgp::crypto::mpi::PublicKey::DSA {
                    p: pgp::crypto::mpi::MPI::new(&[0]),
                    q: pgp::crypto::mpi::MPI::new(&[1]),
                    g: pgp::crypto::mpi::MPI::new(&[2]),
                    y: pgp::crypto::mpi::MPI::new(&[3]),
                },
            )
            .unwrap(),
        );
        let value = PublicKey::convert_spanned(&from, &mut converter).unwrap();

        // Check all spans have been exhausted.
        assert!(converter.next_span().is_err());
        insta_assert!(value);
    }

    #[test]
    fn time_overflow() {
        let max = UNIX_EPOCH + Duration::from_secs(u32::MAX.into());
        let time: Result<Time> = max.try_into();
        assert!(time.is_ok());

        const OVERFLOW_SECS: u64 = u32::MAX as u64 + 1;
        let overflow = UNIX_EPOCH + Duration::from_secs(OVERFLOW_SECS);
        let time: Result<Time> = overflow.try_into();
        assert!(matches!(
            time,
            Err(Error::TimeOverflow {
                secs: OVERFLOW_SECS
            })
        ))
    }

    #[test]
    fn mpi_overflow() {
        const LENGTH_MAX_BITS: u16 = u16::MAX;
        const LENGTH_MAX_BYTES: usize = (LENGTH_MAX_BITS as usize + 1) / 8;
        const BYTE_ALL_ONES: u8 = 0xFF;

        let max = {
            let mut bytes = vec![BYTE_ALL_ONES; LENGTH_MAX_BYTES];
            // Set the first bit to 0, or the length field will overflow.
            bytes[0] = 0b0111_1111;
            pgp::crypto::mpi::MPI::new(bytes.as_slice())
        };
        let mut context = Context::new();
        let mut converter = Converter::new(&mut context, vec![1; 2]);
        assert!(Mpi::convert(&max, &mut converter).is_ok());

        let overflow = {
            let bytes = vec![BYTE_ALL_ONES; LENGTH_MAX_BYTES];
            pgp::crypto::mpi::MPI::new(bytes.as_slice())
        };
        let mut context = Context::new();
        let mut converter = Converter::new(&mut context, vec![1; 2]);
        const OVERFLOW_BITS: usize = LENGTH_MAX_BITS as usize + 1;
        assert!(matches!(
            Mpi::convert(&overflow, &mut converter),
            Err(Error::MpiLengthOverflow {
                bits: OVERFLOW_BITS
            })
        ));
    }
}
