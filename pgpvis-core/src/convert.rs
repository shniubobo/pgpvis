//! Utility structs to convert from [`sequoia_openpgp`]'s data structures into
//! our own ones in [`packet`](crate::packet).

use std::marker::PhantomData;
use std::result::Result as StdResult;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use enumflags2::BitFlags;
use seq_macro::seq;
use sequoia_openpgp::{
    self as pgp, packet::key as pgp_key, parse::PacketParser, serialize::MarshalInto,
};

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
            pgp::Packet::Signature(body) => {
                AnyPacket::Signature(convert_packet!(header, body, converter))
            }
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

macro_rules! convert_sig {
    ($sig:ident => $to:ty, $converter:ident) => {{
        let version = $converter.next_span_with(PhantomData)?;
        let type_id = SignatureTypeId::convert_spanned(&$sig.typ(), $converter)?;
        let pub_key_algo_id = $converter.next_span_with(PhantomData)?;
        let hash_algo_id = HashAlgorithmId::convert_spanned(&$sig.hash_algo(), $converter)?;
        let hashed_length = $converter.next_span_with(Self::area_length($sig.hashed_area())?)?;
        let hashed_subpackets =
            SignatureSubpackets::convert_spanned($sig.hashed_area(), $converter)?;
        let unhashed_length =
            $converter.next_span_with(Self::area_length($sig.unhashed_area())?)?;
        let unhashed_subpackets =
            SignatureSubpackets::convert_spanned($sig.unhashed_area(), $converter)?;
        let hash_prefix = $converter.spanned(|converter| {
            // `sequoia-openpgp` represents the prefix with two
            // fields: `digest_prefix1`, `digest_prefix2`.
            converter.next_span()?;
            converter.next_span()?;
            Ok(*$sig.digest_prefix())
        })?;
        let sig: SignatureVersion4<$to> = SignatureVersion4 {
            version,
            type_id,
            pub_key_algo_id,
            hash_algo_id,
            hashed_length,
            hashed_subpackets,
            unhashed_length,
            unhashed_subpackets,
            hash_prefix,
            mpis: <$to as PublicKeyAlgorithm>::SignatureMpis::convert_spanned(
                $sig.mpis(),
                $converter,
            )?,
        };
        sig.into()
    }};
}

impl Convert<pgp::packet::Signature> for Signature {
    fn convert(sig: &pgp::packet::Signature, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        let ret = match sig {
            pgp::packet::Signature::V4(sig) => match sig.mpis() {
                pgp::crypto::mpi::Signature::RSA { .. } => {
                    convert_sig!(sig => RsaEncryptSign, converter)
                }
                pgp::crypto::mpi::Signature::EdDSA { .. } => {
                    convert_sig!(sig => EdDsaLegacy, converter)
                }
                pgp::crypto::mpi::Signature::Ed25519 { .. } => {
                    convert_sig!(sig => Ed25519, converter)
                }
                _ => {
                    let version = converter.next_span_with(PhantomData)?;
                    let type_id = SignatureTypeId::convert_spanned(&sig.typ(), converter)?;
                    let pub_key_algo_id = converter.next_span_with(PhantomData)?;
                    let hash_algo_id =
                        HashAlgorithmId::convert_spanned(&sig.hash_algo(), converter)?;
                    let hashed_length =
                        converter.next_span_with(Self::area_length(sig.hashed_area())?)?;
                    let hashed_subpackets =
                        SignatureSubpackets::convert_spanned(sig.hashed_area(), converter)?;
                    let unhashed_length =
                        converter.next_span_with(Self::area_length(sig.unhashed_area())?)?;
                    let unhashed_subpackets =
                        SignatureSubpackets::convert_spanned(sig.unhashed_area(), converter)?;
                    let hash_prefix = converter.spanned(|converter| {
                        // `sequoia-openpgp` represents the prefix with two
                        // fields: `digest_prefix1`, `digest_prefix2`.
                        converter.next_span()?;
                        converter.next_span()?;
                        Ok(*sig.digest_prefix())
                    })?;
                    let sig: SignatureVersion4<PublicKeyAlgorithmUnimplemented> =
                        SignatureVersion4 {
                            version,
                            type_id,
                            pub_key_algo_id,
                            hash_algo_id,
                            hashed_length,
                            hashed_subpackets,
                            unhashed_length,
                            unhashed_subpackets,
                            hash_prefix,
                            mpis: converter.spanned(|converter| {
                                // Exhaust all remaining spans.
                                while converter.next_span().is_ok() {}
                                Ok(SignatureMpisUnimplemented)
                            })?,
                        };
                    sig.into()
                }
            },
            _ => Err(Error::Unimplemented(format!(
                "signature version {}",
                sig.version()
            )))?,
        };
        Ok(ret)
    }
}

impl Signature {
    fn area_length(area: &pgp::packet::signature::subpacket::SubpacketArea) -> Result<u16> {
        // This is how `sequoia-openpgp` calculates the length. The length is
        // not stored. See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1192.
        // TODO: Once the length is exposed by `sequoia`, change to use that.
        let length = area.serialized_len();
        if length > u16::MAX as _ {
            return Err(Error::SubpacketAreaLengthOverflow { length });
        }
        Ok(length as _)
    }
}

impl Convert<pgp::packet::signature::subpacket::SubpacketArea> for SignatureSubpackets {
    fn convert(
        from: &pgp::packet::signature::subpacket::SubpacketArea,
        converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        from.iter()
            .map(|subpacket| SignatureSubpacket::convert_spanned(subpacket, converter))
            .collect::<Result<Vec<_>>>()
            .map(|subpackets| subpackets.into())
    }
}

impl Convert<pgp::packet::signature::subpacket::Subpacket> for SignatureSubpacket {
    fn convert(
        from: &pgp::packet::signature::subpacket::Subpacket,
        converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // TODO: Implement conversion to `SignatureSubpacketLength` when
        // `sequoia-openpgp` exposes the length.
        // Blocked by: https://gitlab.com/sequoia-pgp/sequoia/-/issues/1192
        let length = converter.next_span_with(SignatureSubpacketLength::One(0))?;
        let type_id = SignatureSubpacketTypeIdOctet::convert_spanned(from, converter)?;
        let data = SignatureSubpacketData::convert_spanned(from.value(), converter)?;
        Ok(Self {
            length,
            type_id,
            data,
        })
    }
}

impl Convert<pgp::packet::signature::subpacket::Subpacket> for SignatureSubpacketTypeIdOctet {
    fn convert(
        from: &pgp::packet::signature::subpacket::Subpacket,
        converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        converter.next_span()?;
        Ok(Self {
            critical: from.critical(),
            type_id: PhantomData,
        })
    }
}

// This is a gigantic function, but I think we have no choice.
impl Convert<pgp::packet::signature::subpacket::SubpacketValue> for SignatureSubpacketData {
    fn convert(
        from: &pgp::packet::signature::subpacket::SubpacketValue,
        converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        use pgp::packet::signature::subpacket::SubpacketValue as Subpkt;

        let ret = match from {
            Subpkt::SignatureCreationTime(timestamp) => {
                Self::SignatureCreationTime(Time::convert_spanned(timestamp, converter)?)
            }
            Subpkt::SignatureExpirationTime(duration) => {
                Self::SignatureExpirationTime(Time::convert_spanned(duration, converter)?)
            }
            Subpkt::ExportableCertification(exportable) => {
                Self::ExportableCertification(converter.next_span_with(*exportable)?)
            }
            Subpkt::TrustSignature { level, trust } => Self::TrustSignature {
                level: converter.next_span_with(*level)?,
                amount: converter.next_span_with(*trust)?,
            },
            Subpkt::RegularExpression(items) => Self::RegularExpression(
                // RFC 9580 requires that `items` is UTF-8, but we still use
                // the `lossy` variant to accept non-UTF-8 characters, so that
                // we need not care about how to display invalid strings. The
                // same is also true for many `Vec<u8>`s or `[u8]`s below.
                converter.next_span_with(String::from_utf8_lossy(items).into_owned())?,
            ),
            Subpkt::Revocable(revocable) => Self::Revocable(converter.next_span_with(*revocable)?),
            Subpkt::KeyExpirationTime(duration) => {
                Self::KeyExpirationTime(Time::convert_spanned(duration, converter)?)
            }
            Subpkt::PreferredSymmetricAlgorithms(algos) => Self::PreferredSymmetricCiphers(
                Vec::<Span<SymmetricKeyAlgorithmId>>::convert_spanned(&&**algos, converter)?,
            ),
            Subpkt::RevocationKey(key) => {
                let (pub_key_algo_id, fingerprint) = key.revoker();
                let fingerprint = {
                    let fingerprint = Fingerprint::convert_spanned(fingerprint, converter)?;
                    match fingerprint.inner {
                        Fingerprint::Version4(version4) => fingerprint.replace_with(version4),
                        _ => Err(Error::WrongFingerprintVersion {
                            expected: 4,
                            got: fingerprint.inner.version(),
                        })?,
                    }
                };

                Self::RevocationKey {
                    class: converter.next_span_with(key.class())?,
                    pub_key_algo_id: PublicKeyAlgorithmId::convert_spanned(
                        &pub_key_algo_id,
                        converter,
                    )?,
                    fingerprint,
                }
            }
            Subpkt::Issuer(key_id) => Self::IssuerKeyId(KeyId::convert_spanned(key_id, converter)?),
            Subpkt::NotationData(notation_data) => Self::NotationData {
                flags: BitFlags::<NotationDataFlag>::convert_spanned(
                    notation_data.flags(),
                    converter,
                )?,
                name_length: converter.next_span_with(notation_data.name().len().try_into()?)?,
                value_length: converter.next_span_with(notation_data.value().len().try_into()?)?,
                name: converter.next_span_with(notation_data.name().to_string())?,
                value: converter.next_span_with(notation_data.value().to_vec())?,
            },
            Subpkt::PreferredHashAlgorithms(algos) => Self::PreferredHashAlgorithms(
                Vec::<Span<HashAlgorithmId>>::convert_spanned(&&**algos, converter)?,
            ),
            Subpkt::PreferredCompressionAlgorithms(algos) => Self::PreferredCompressionAlgorithms(
                Vec::<Span<CompressionAlgorithmId>>::convert_spanned(&&**algos, converter)?,
            ),
            Subpkt::KeyServerPreferences(flags) => Self::KeyServerPreferences(
                KeyServerPreferencesFlags::convert_spanned(flags, converter)?,
            ),
            Subpkt::PreferredKeyServer(uri) => Self::PreferredKeyServer(
                converter.next_span_with(String::from_utf8_lossy(uri).to_string())?,
            ),
            Subpkt::PrimaryUserID(primary) => {
                Self::PrimaryUserId(converter.next_span_with(*primary)?)
            }
            Subpkt::PolicyURI(uri) => {
                Self::PolicyUri(converter.next_span_with(String::from_utf8_lossy(uri).to_string())?)
            }
            Subpkt::KeyFlags(flags) => {
                Self::KeyFlags(KeyFlagsFlags::convert_spanned(flags, converter)?)
            }
            Subpkt::SignersUserID(user_id) => Self::SignerUserId(
                converter.next_span_with(String::from_utf8_lossy(user_id).to_string())?,
            ),
            Subpkt::ReasonForRevocation { code, reason } => Self::RevocationReason {
                code: RevocationCode::convert_spanned(code, converter)?,
                reason: converter.next_span_with(String::from_utf8_lossy(reason).to_string())?,
            },
            Subpkt::Features(flags) => {
                Self::Features(FeaturesFlags::convert_spanned(flags, converter)?)
            }
            Subpkt::SignatureTarget {
                pk_algo,
                hash_algo,
                digest,
            } => Self::SignatureTarget {
                pub_key_algo_id: PublicKeyAlgorithmId::convert_spanned(pk_algo, converter)?,
                hash_algo_id: HashAlgorithmId::convert_spanned(hash_algo, converter)?,
                hash: converter.next_span_with(digest.clone())?,
            },
            Subpkt::EmbeddedSignature(signature) => {
                let signature = {
                    let signature = Signature::convert_spanned(signature, converter)?;
                    let (span, signature) = signature.take();
                    span.replace_with(Box::new(signature))
                };
                Self::EmbeddedSignature(signature)
            }
            Subpkt::IssuerFingerprint(fingerprint) => Self::IssuerFingerprint {
                version: converter.next_span_with(PhantomData)?,
                fingerprint: Fingerprint::convert_spanned(fingerprint, converter)?,
            },
            Subpkt::IntendedRecipient(fingerprint) => Self::IntendedRecipientFingerprint {
                version: converter.next_span_with(PhantomData)?,
                fingerprint: Fingerprint::convert_spanned(fingerprint, converter)?,
            },
            Subpkt::PreferredAEADCiphersuites(suites) => Self::PreferredAeadCiphersuites(
                Vec::<Span<AeadCiphersuite>>::convert_spanned(&&**suites, converter)?,
            ),
            // We cannot just display an unimplemented subpacket, because we don't know
            // how many spans we should advance.
            _ => Err(Error::Unimplemented(format!(
                "unimplemented signature subpacket {}",
                from.tag(),
            )))?,
        };
        Ok(ret)
    }
}

impl Convert<pgp::packet::signature::subpacket::NotationDataFlags> for BitFlags<NotationDataFlag> {
    fn convert_spanned(
        from: &pgp::packet::signature::subpacket::NotationDataFlags,
        converter: &mut Converter,
    ) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let flags = {
            let flags: [u8; 4] = from.as_bitfield().as_bytes().try_into()?;
            u32::from_be_bytes(flags)
        };
        converter.next_span_with(Self::from_bits(flags).map_err(Into::<BitflagsError>::into)?)
    }

    fn convert(
        _from: &pgp::packet::signature::subpacket::NotationDataFlags,
        _converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

macro_rules! gen_bitflags_convert_impls {
    { $( $from:ty => $to:ty : $n_octets:literal ),+ $(,)? } => {
        $(
            impl Convert<$from> for $to {
                fn convert_spanned(from: &$from, converter: &mut Converter) -> Result<Span<Self>>
                where
                    Self: Sized,
                {
                    let flags = from.as_bitfield().as_bytes();
                    let span = converter.next_span()?;
                    let offset = span.offset;

                    seq!(N in 0..$n_octets {
                        let mut flags_exists_~N = true;
                        let flags~N = {
                            let flags = match flags.get(N) {
                                Some(flags) => flags,
                                None => {
                                    flags_exists_~N = false;
                                    &0
                                }
                            };
                            BitFlags::<$to~N>::from_bits(*flags)
                                .map_err(Into::<BitflagsError>::into)?
                        };
                        // We still increase the offset; that the length is zero
                        // is already enough to express that the span is
                        // non-existent.
                        let span~N = match flags_exists_~N {
                            true => Span::new(offset + N, 1, flags~N),
                            false => Span::new(offset + N, 0, flags~N),
                        };
                    });

                    seq!(N in 0..$n_octets {
                        Ok(span.replace_with(Self(
                            #( span~N, )*
                        )))
                    })
                }

                fn convert(_from: &$from, _converter: &mut Converter) -> Result<Self>
                where
                    Self: Sized,
                {
                    unreachable!()
                }
            }
        )+
    };
}

gen_bitflags_convert_impls! {
    pgp::types::KeyServerPreferences => KeyServerPreferencesFlags: 1,
    pgp::types::KeyFlags => KeyFlagsFlags: 2,
    pgp::types::Features => FeaturesFlags: 1,
}

impl Convert<&[(pgp::crypto::SymmetricAlgorithm, pgp::crypto::AEADAlgorithm)]>
    for Vec<Span<AeadCiphersuite>>
{
    fn convert_spanned(
        from: &&[(pgp::crypto::SymmetricAlgorithm, pgp::crypto::AEADAlgorithm)],
        converter: &mut Converter,
    ) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let span = converter.next_span()?;
        let offset = span.offset;

        let ret = from
            .iter()
            // From `sequoia-openpgp` to our types.
            .map(|(sym, aead)| ((*sym).into(), (*aead).into()))
            .map(|(sym, aead): (u8, u8)| {
                (
                    sym.try_into()
                        .map_err(|_| Error::Unimplemented(format!("symmetric algorithm {sym}",))),
                    aead.try_into()
                        .map_err(|_| Error::Unimplemented(format!("AEAD algorithm {aead}",))),
                )
            })
            .enumerate()
            // Make every octet spanned.
            .map(|(idx, (sym, aead))| {
                (
                    sym.map(|sym| Span::new(offset + idx * 2, 1, sym)),
                    aead.map(|aead| Span::new(offset + 1 + idx * 2, 1, aead)),
                )
            })
            // Merge results.
            .map(|result| match result {
                (Ok(sym), Ok(aead)) => Ok((sym, aead).into()),
                (Err(err), _) | (_, Err(err)) => Err(err),
            })
            .enumerate()
            .map(|(idx, suite)| suite.map(|suite| Span::new(offset + idx * 2, 2, suite)))
            .collect::<Result<_>>()?;

        Ok(span.replace_with(ret))
    }

    fn convert(
        _from: &&[(pgp::crypto::SymmetricAlgorithm, pgp::crypto::AEADAlgorithm)],
        _converter: &mut Converter,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

macro_rules! err_wrong_mpis {
    ($from:ident) => {
        Err(Error::WrongSignatureMpis {
            expected: Self::DISPLAY,
            got: format!("{:#?}", $from),
        })
    };
}

impl Convert<pgp::crypto::mpi::Signature> for SignatureMpisRsa {
    fn convert(from: &pgp::crypto::mpi::Signature, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        if let pgp::crypto::mpi::Signature::RSA { s } = from {
            let s = Mpi::convert_spanned(s, converter)?;
            return Ok(Self(s));
        }

        err_wrong_mpis!(from)
    }
}

impl Convert<pgp::crypto::mpi::Signature> for SignatureMpisRS {
    fn convert(from: &pgp::crypto::mpi::Signature, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        if let pgp::crypto::mpi::Signature::DSA { r, s }
        | pgp::crypto::mpi::Signature::ECDSA { r, s }
        | pgp::crypto::mpi::Signature::EdDSA { r, s } = from
        {
            let r = Mpi::convert_spanned(r, converter)?;
            let s = Mpi::convert_spanned(s, converter)?;
            return Ok(Self { r, s });
        }

        err_wrong_mpis!(from)
    }
}

impl Convert<pgp::crypto::mpi::Signature> for SignatureMpisEd25519 {
    fn convert(from: &pgp::crypto::mpi::Signature, converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        if let pgp::crypto::mpi::Signature::Ed25519 { s } = from {
            let s = converter.next_span_with(**s)?;
            return Ok(Self(s));
        }

        err_wrong_mpis!(from)
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
                        while converter.next_span().is_ok() {}
                        Ok(PublicKeyAlgorithmUnimplemented)
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

impl Convert<pgp::types::Timestamp> for Time {
    fn convert_spanned(
        from: &pgp::types::Timestamp,
        converter: &mut Converter,
    ) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let time = (*from).into();
        converter.next_span_with(Self(time))
    }

    fn convert(_from: &pgp::types::Timestamp, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl Convert<pgp::types::Duration> for Time {
    fn convert_spanned(from: &pgp::types::Duration, converter: &mut Converter) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let time = (*from).into();
        converter.next_span_with(Self(time))
    }

    fn convert(_from: &pgp::types::Duration, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

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

impl Convert<pgp::Fingerprint> for Fingerprint {
    fn convert_spanned(from: &pgp::Fingerprint, converter: &mut Converter) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let ret = match from {
            pgp::Fingerprint::V6(bytes) => Self::Version6(FingerprintVersion6(*bytes)),
            pgp::Fingerprint::V4(bytes) => Self::Version4(FingerprintVersion4(*bytes)),
            pgp::Fingerprint::Unknown {
                version: Some(3),
                bytes,
            } => {
                let length = bytes.len();
                if length != Fingerprint::VERSION_3_LEN {
                    Err(Error::WrongFingerprintLength { version: 3, length })?;
                }
                Self::Version3(FingerprintVersion3((**bytes).try_into().unwrap()))
            }
            pgp::Fingerprint::Unknown {
                version: Some(version),
                ..
            } => Err(Error::Unimplemented(format!(
                "fingerprint version {version}"
            )))?,
            _ => Err(Error::Unimplemented(
                "fingerprint version unknown".to_string(),
            ))?,
        };
        converter.next_span_with(ret)
    }

    fn convert(_from: &pgp::Fingerprint, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl Convert<pgp::KeyID> for KeyId {
    fn convert_spanned(from: &pgp::KeyID, converter: &mut Converter) -> Result<Span<Self>>
    where
        Self: Sized,
    {
        let octets = match from {
            pgp::KeyID::Long(octets) => converter.next_span_with(*octets)?,
            _ => Err(Error::InvalidKeyId)?,
        };
        Ok(octets.replace_with(Self(octets.inner)))
    }

    fn convert(_from: &pgp::KeyID, _converter: &mut Converter) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
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

macro_rules! gen_convert_vec_span_id {
    { $( $from:ty => $to:ty ),+ $(,)? } => {
        $(
            impl Convert<&[$from]> for Vec<Span<$to>> {
                fn convert_spanned(
                    from: &&[$from],
                    converter: &mut Converter,
                ) -> Result<Span<Self>>
                where
                    Self: Sized,
                {
                    let span = converter.next_span()?;
                    let Span { offset, .. } = span;
                    let ids = from
                        .iter()
                        .map(|id| {
                            // From `sequoia-openpgp` to our type.
                            let id: u8 = (*id).into();
                            id.try_into()
                                .map_err(|_| Error::Unimplemented(id.to_string()))
                        })
                        .enumerate()
                        .map(|(idx, id)| {
                            // Make every octet spanned.
                            id.map(|id| Span {
                                offset: offset + idx,
                                length: 1,
                                inner: id,
                            })
                        })
                        .collect::<Result<_>>()?;
                    Ok(span.replace_with(ids))
                }

                fn convert(
                    _from: &&[$from],
                    _converter: &mut Converter,
                ) -> Result<Self>
                where
                    Self: Sized,
                {
                    unreachable!()
                }
            }
        )+
    };
}

gen_convert_vec_span_id! {
    pgp::crypto::SymmetricAlgorithm => SymmetricKeyAlgorithmId,
    pgp::types::CompressionAlgorithm => CompressionAlgorithmId,
    pgp::crypto::HashAlgorithm => HashAlgorithmId,
    pgp::crypto::AEADAlgorithm => AeadAlgorithmId,
}

macro_rules! gen_id_convert_impls {
    { $( $from:ty => $to:ty ),+ $(,)? } => {
        $(
            impl Convert<$from> for $to {
                fn convert_spanned(
                    from: &$from,
                    converter: &mut Converter,
                ) -> Result<Span<Self>>
                where
                    Self: Sized,
                {
                    let id: u8 = (*from).into();
                    let id = id
                        .try_into()
                        .map_err(|_| Error::Unimplemented(id.to_string()))?;
                    converter.next_span_with(id)
                }

                fn convert(_from: &$from, _converter: &mut Converter) -> Result<Self>
                where
                    Self: Sized,
                {
                    unreachable!()
                }
            }
        )*
    };
}

gen_id_convert_impls! {
    pgp::types::SignatureType => SignatureTypeId,
    pgp::packet::signature::subpacket::SubpacketTag => SignatureSubpacketTypeId,
    pgp::types::ReasonForRevocation => RevocationCode,
    pgp::crypto::PublicKeyAlgorithm => PublicKeyAlgorithmId,
    pgp::crypto::SymmetricAlgorithm => SymmetricKeyAlgorithmId,
    pgp::types::CompressionAlgorithm => CompressionAlgorithmId,
    pgp::crypto::HashAlgorithm => HashAlgorithmId,
    pgp::crypto::AEADAlgorithm => AeadAlgorithmId,
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

    use pgp::parse::{
        buffered_reader::{BufferedReader, Memory},
        Cookie, PacketHeaderParser, PacketParserSettings, PacketParserState, Parse,
    };
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
    ///
    /// 1. A given type (1) can be [`Convert`]ed from a certain value (2)
    /// 2. The conversion consumes an exact number of fields (3); and
    /// 3. Optionally (when the optional arguments are provided), that field
    ///    number (3) is the same as what [`sequoia_openpgp`] would return.
    ///
    /// To assert the third, the type of the value (2) must have a method
    /// `parse` that takes either an owned [`PacketHeaderParser`] or a `&mut` to
    /// it. Alternatively, it must have a `_parse` method that take a `&mut` to
    /// [`PacketHeaderParser`].
    ///
    /// To call this macro:
    ///
    /// ```text
    /// assert_convert! {
    ///     [function name of test] {
    ///         [2] => [3] @ [1]
    ///     } [optional arguments]
    ///
    ///     [repeat for other tests]
    /// }
    /// ```
    ///
    /// The optional arguments can be one of:
    ///
    /// ```text
    /// @ { map([args]) -> [type of [2]] }
    /// // OR
    /// @ { map_ref_mut([args]) -> [type of [2]] }
    /// // OR
    /// @ { map__parse([args]) -> [type of [2]] }
    /// ```
    ///
    /// ..., where the first variant passes an owned [`PacketHeaderParser`] to
    /// `parse`, while the other two pass a `&mut`. The arguments are passed to
    /// `parse` (or `_parse` for the third variant) verbatim, either after the
    /// [`PacketHeaderParser`] (the first or second variant) or before it
    /// (third).
    ///
    /// For examples of `parse`, see [`pgp::packet::Signature::parse`] for one
    /// that takes an owned [`PacketHeaderParser`], and
    /// [`pgp::packet::signature::subpacket::Subpacket::parse`] for one that
    /// takes a `&mut`. `_parse` in specific refers to
    /// [`pgp::crypto::mpi::PublicKey::_parse`].
    macro_rules! assert_convert {
        { $( $fn_name:ident $conversion:tt $(@ $option:tt )? )* } => {
            $(
                #[test]
                fn $fn_name() {
                    assert_convert!($(@$option)? $conversion);
                }
            )*
        };

        (@ { map $args:tt -> $parse:ty } { $from:expr => $fields:literal @ $to:ty }) => {
            assert_convert!(@assert_map $args, $parse, $from, $fields);
            assert_convert!(@snapshot $from, $fields, $to);
        };

        (@ { map_ref_mut $args:tt -> $parse:ty } { $from:expr => $fields:literal @ $to:ty }) => {
            assert_convert!(@assert_map_ref_mut $args, $parse, $from, $fields);
            assert_convert!(@snapshot $from, $fields, $to);
        };

        (@ { map__parse $args:tt -> $parse:ty } { $from:expr => $fields:literal @ $to:ty }) => {
            assert_convert!(@assert_map__parse $args, $parse, $from, $fields);
            assert_convert!(@snapshot $from, $fields, $to);
        };

        ({ $from:expr => $fields:literal @ $to:ty }) => {
            assert_convert!(@snapshot $from, $fields, $to);
        };

        // Assert that the field number provided is the same as what `sequoia`
        // would return. Some types does not implement `MarshalInto` or has
        // `parse`, so we need an option to enable this assertion.
        (@assert_map ( $( $args:expr ),* ), $parse:ty, $from:expr, $fields:literal) => {
            let bytes = $from.to_vec().unwrap();

            let parser = new_parser(&bytes);
            let parser = <$parse>::parse(parser, $($args),*).unwrap();

            let n_fields = parser.map.unwrap().iter().count();
            assert_eq!(n_fields, $fields);
        };

        // Same as above, except that a `&mut` to `PacketHeaderParser` is
        // instead passed.
        (@assert_map_ref_mut ( $( $args:expr ),* ), $parse:ty, $from:expr, $fields:literal) => {
            let bytes = $from.to_vec().unwrap();

            let mut parser = new_parser(&bytes);
            let _ = <$parse>::parse(&mut parser, $($args),*).unwrap();

            let n_fields = parser.map.unwrap().iter().count();
            assert_eq!(n_fields, $fields);
        };

        // Same as above, except that `_parse` is called instead.
        (@assert_map__parse ( $( $args:expr ),* ), $parse:ty, $from:expr, $fields:literal) => {
            let bytes = $from.to_vec().unwrap();

            let mut parser = new_parser(&bytes);
            let _ = <$parse>::_parse($($args,)* &mut parser).unwrap();

            let n_fields = parser.map.unwrap().iter().count();
            assert_eq!(n_fields, $fields);
        };

        (@snapshot $from:expr, $fields:literal, $to:ty) => {
            let mut context = Context::new();
            let mut converter = Converter::new(&mut context, vec![1; $fields]);
            let value = <$to>::convert_spanned(&$from, &mut converter).unwrap();

            // Ensure exact number of fields.
            assert!(converter.next_span().is_err());

            insta_assert!(value);
        };
    }

    fn new_parser(bytes: &[u8]) -> PacketHeaderParser {
        let buffered_reader = Memory::with_cookie(bytes, Cookie::default()).into_boxed();
        let settings = PacketParserSettings {
            map: true,
            ..Default::default()
        };
        let state = PacketParserState::new(settings);

        // Almost the same as `PacketHeaderParser::new_naked`, with `state`
        // changed.
        PacketHeaderParser::new(
            buffered_reader,
            state,
            vec![0],
            pgp::packet::Header::new(
                pgp::packet::header::CTB::new(pgp::packet::Tag::Reserved),
                pgp::packet::header::BodyLength::Full(0),
            ),
            Vec::new(),
        )
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

        signature_v4_rsa {
            pgp::packet::Signature::V4(
                pgp::packet::signature::Signature4::new(
                    pgp::types::SignatureType::Text,
                    pgp::crypto::PublicKeyAlgorithm::RSAEncryptSign,
                    pgp::crypto::HashAlgorithm::SHA256,
                    pgp::packet::signature::subpacket::SubpacketArea::new(
                        vec![
                            pgp::packet::signature::subpacket::Subpacket::new(
                                pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                                true,
                            ).unwrap(),
                        ]
                    ).unwrap(),
                    pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                    [0, 1],
                    pgp::crypto::mpi::Signature::RSA {
                        s: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                    },
                )
            ) => 13 @ Signature
        } @ { map() -> pgp::packet::Signature }

        signature_v4_eddsa {
            pgp::packet::Signature::V4(
                pgp::packet::signature::Signature4::new(
                    pgp::types::SignatureType::Text,
                    pgp::crypto::PublicKeyAlgorithm::EdDSA,
                    pgp::crypto::HashAlgorithm::SHA256,
                    pgp::packet::signature::subpacket::SubpacketArea::new(
                        vec![
                            pgp::packet::signature::subpacket::Subpacket::new(
                                pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                                true,
                            ).unwrap(),
                        ]
                    ).unwrap(),
                    pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                    [0, 1],
                    pgp::crypto::mpi::Signature::EdDSA {
                        r: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                        s: pgp::crypto::mpi::MPI::new(&[4, 5, 6]),
                    },
                )
            ) => 15 @ Signature
        } @ { map() -> pgp::packet::Signature }

        signature_v4_ed25519 {
            pgp::packet::Signature::V4(
                pgp::packet::signature::Signature4::new(
                    pgp::types::SignatureType::Text,
                    pgp::crypto::PublicKeyAlgorithm::Ed25519,
                    pgp::crypto::HashAlgorithm::SHA256,
                    pgp::packet::signature::subpacket::SubpacketArea::new(
                        vec![
                            pgp::packet::signature::subpacket::Subpacket::new(
                                pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                                true,
                            ).unwrap(),
                        ]
                    ).unwrap(),
                    pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                    [0, 1],
                    pgp::crypto::mpi::Signature::Ed25519 {
                        s: Box::new([1; 64]),
                    },
                )
            ) => 12 @ Signature
        } @ { map() -> pgp::packet::Signature }

        // Using DSA as we will not implement it anytime soon.
        signature_v4_unimplemented {
            pgp::packet::Signature::V4(
                pgp::packet::signature::Signature4::new(
                    pgp::types::SignatureType::Text,
                    #[expect(deprecated)]
                    pgp::crypto::PublicKeyAlgorithm::DSA,
                    pgp::crypto::HashAlgorithm::SHA256,
                    pgp::packet::signature::subpacket::SubpacketArea::new(
                        vec![
                            pgp::packet::signature::subpacket::Subpacket::new(
                                pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                                true,
                            ).unwrap(),
                        ]
                    ).unwrap(),
                    pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                    [0, 1],
                    pgp::crypto::mpi::Signature::DSA {
                        r: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                        s: pgp::crypto::mpi::MPI::new(&[4, 5, 6]),
                    },
                )
            // Any number greater than 10 passes the test, because all
            // remaining spans are drained in the case of an unimplemented
            // signature, no matter how much there is. TODO: Find a way to
            // ensure the number is the same as what `sequoia-openpgp` would
            // return.
            ) => 15 @ Signature
        } @ { map() -> pgp::packet::Signature }

        signature_subpackets_empty {
            pgp::packet::signature::subpacket::SubpacketArea::new(
                vec![]
            ).unwrap() => 0 @ SignatureSubpackets
        } @ {
            map_ref_mut(0, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::SubpacketArea
        }

        signature_subpackets_1 {
            pgp::packet::signature::subpacket::SubpacketArea::new(
                vec![
                    pgp::packet::signature::subpacket::Subpacket::new(
                        pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                        true,
                    ).unwrap(),
                ]
            ).unwrap() => 3 @ SignatureSubpackets
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::SubpacketArea
        }

        signature_subpackets_3 {
            pgp::packet::signature::subpacket::SubpacketArea::new(
                vec![
                    pgp::packet::signature::subpacket::Subpacket::new(
                        pgp::packet::signature::subpacket::SubpacketValue::Revocable(false),
                        true,
                    ).unwrap(),
                    pgp::packet::signature::subpacket::Subpacket::new(
                        pgp::packet::signature::subpacket::SubpacketValue::TrustSignature {
                            level: 255,
                            trust: 120,
                        },
                        false,
                    ).unwrap(),
                    pgp::packet::signature::subpacket::Subpacket::new(
                        pgp::packet::signature::subpacket::SubpacketValue::PrimaryUserID(true),
                        true,
                    ).unwrap(),
                ]
            ).unwrap() => 10 @ SignatureSubpackets
        } @ {
            map_ref_mut(10, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::SubpacketArea
        }

        // `SignatureSubpacket` are tested below instead of
        // `SignatureSubpacketData`, because `SubpacketValue` does not
        // implement `parse` and thus cannot be tested with `map`.

        sig_subpkt_signature_creation_time {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::SignatureCreationTime(
                    pgp::types::Timestamp::from(0),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(6, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_signature_expiration_time {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::SignatureExpirationTime(
                    pgp::types::Duration::from(0),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(6, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_exportable_certification {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::ExportableCertification(
                    true,
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_trust_signature {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::TrustSignature {
                    level: 255,
                    trust: 60,
                },
                true,
            ).unwrap() => 4 @ SignatureSubpacket
        } @ {
            map_ref_mut(4, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_regular_expression {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::RegularExpression(
                    "foo".as_bytes().to_vec(),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            // "foo" is null-terminated.
            map_ref_mut(6, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_revocable {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::Revocable(
                    false,
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_key_expiration_time {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::KeyExpirationTime(
                    pgp::types::Duration::from(1),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(6, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        // TODO: Test empty `Vec`s.
        sig_subpkt_signature_preferred_symmetric_ciphers {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PreferredSymmetricAlgorithms(
                    vec![
                        pgp::crypto::SymmetricAlgorithm::AES256,
                        pgp::crypto::SymmetricAlgorithm::AES192,
                        pgp::crypto::SymmetricAlgorithm::AES128,
                    ],
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(5, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_revocation_key {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::RevocationKey(
                    pgp::types::RevocationKey::new(
                        pgp::crypto::PublicKeyAlgorithm::Ed25519,
                        pgp::Fingerprint::V4([1; 20]),
                        true,
                    ),
                ),
                true,
            ).unwrap() => 5 @ SignatureSubpacket
        } @ {
            map_ref_mut(24, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_issuer_key_id {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::Issuer(
                    pgp::KeyID::from_bytes(&[1; 8]),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(10, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_notation_data {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::NotationData(
                    pgp::packet::signature::subpacket::NotationData::new(
                        "foo@example.com",
                        "DEADBEEF",
                        Some(
                            pgp::packet::signature::subpacket::NotationDataFlags::empty()
                                .set_human_readable()
                        ),
                    ),
                ),
                true,
            ).unwrap() => 7 @ SignatureSubpacket
        } @ {
            map_ref_mut(37, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_preferred_hash_algorithms {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PreferredHashAlgorithms(
                    vec![
                        pgp::crypto::HashAlgorithm::SHA512,
                        pgp::crypto::HashAlgorithm::SHA384,
                        pgp::crypto::HashAlgorithm::SHA256,
                    ],
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(5, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_preferred_compression_algorithms {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PreferredCompressionAlgorithms(
                    vec![
                        pgp::types::CompressionAlgorithm::Zlib,
                        pgp::types::CompressionAlgorithm::Zip,
                        pgp::types::CompressionAlgorithm::Uncompressed,
                    ],
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(5, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_key_server_preferences {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::KeyServerPreferences(
                    pgp::types::KeyServerPreferences::empty().set_no_modify(),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_preferred_key_server {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PreferredKeyServer(
                    "hkps://keyserver.example.com/".as_bytes().to_vec(),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(31, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_primary_user_id {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PrimaryUserID(
                    true,
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_policy_uri {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PolicyURI(
                    "https://example.com/policy/".as_bytes().to_vec(),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(29, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_key_flags_1 {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::KeyFlags(
                    pgp::types::KeyFlags::new([0b1011_1111]),
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_key_flags_2_zeroed {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::KeyFlags(
                    pgp::types::KeyFlags::new([0b1011_1111, 0]),
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(4, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_key_flags_2 {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::KeyFlags(
                    pgp::types::KeyFlags::new([0b1011_1111, 0b1100]),
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(4, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_signer_user_id {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::SignersUserID(
                    "John <john@example.com>".as_bytes().to_vec(),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(25, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_revocation_reason {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::ReasonForRevocation {
                    code: pgp::types::ReasonForRevocation::UIDRetired,
                    reason: "UID changed.".as_bytes().to_vec(),
                },
                true,
            ).unwrap() => 4 @ SignatureSubpacket
        } @ {
            map_ref_mut(15, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_features {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::Features(
                    pgp::types::Features::new([0x0F]),
                ),
                true,
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(3, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_signature_target {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::SignatureTarget {
                    pk_algo: pgp::crypto::PublicKeyAlgorithm::Ed25519,
                    hash_algo: pgp::crypto::HashAlgorithm::SHA3_512,
                    digest: "DEADBEEF".as_bytes().to_vec(),
                },
                true,
            ).unwrap() => 5 @ SignatureSubpacket
        } @ {
            map_ref_mut(12, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_embedded_signature {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::EmbeddedSignature(
                    pgp::packet::signature::Signature4::new(
                        pgp::types::SignatureType::Text,
                        pgp::crypto::PublicKeyAlgorithm::RSAEncryptSign,
                        pgp::crypto::HashAlgorithm::SHA256,
                        pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                        pgp::packet::signature::subpacket::SubpacketArea::new(vec![]).unwrap(),
                        [0, 1],
                        pgp::crypto::mpi::Signature::RSA {
                            s: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                        },
                    ).into()
                ),
                true,
            ).unwrap() => 12 @ SignatureSubpacket
        }
        // FIXME: Retrieve fields for the embedded signature.
        // @ {
        //     map_ref_mut(17, pgp::crypto::HashAlgorithm::SHA256)
        //         -> pgp::packet::signature::subpacket::Subpacket
        // }

        sig_subpkt_signature_issuer_fingerprint {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::IssuerFingerprint(
                    pgp::Fingerprint::V4([1; 20]),
                ),
                true,
            ).unwrap() => 4 @ SignatureSubpacket
        } @ {
            map_ref_mut(23, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_intended_recipient_fingerprint {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::IntendedRecipient(
                    pgp::Fingerprint::V4([1; 20]),
                ),
                true,
            ).unwrap() => 4 @ SignatureSubpacket
        } @ {
            map_ref_mut(23, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
        }

        sig_subpkt_signature_preferred_aead_ciphersuites {
            pgp::packet::signature::subpacket::Subpacket::new(
                pgp::packet::signature::subpacket::SubpacketValue::PreferredAEADCiphersuites(
                    vec![
                        (
                            pgp::crypto::SymmetricAlgorithm::AES256,
                            pgp::crypto::AEADAlgorithm::EAX,
                        ),
                        (
                            pgp::crypto::SymmetricAlgorithm::AES192,
                            pgp::crypto::AEADAlgorithm::OCB,
                        ),
                        (
                            pgp::crypto::SymmetricAlgorithm::AES128,
                            pgp::crypto::AEADAlgorithm::GCM,
                        ),
                    ],
                ),
                true,
            // Provided as one span, though we have split it into several ones.
            ).unwrap() => 3 @ SignatureSubpacket
        } @ {
            map_ref_mut(8, pgp::crypto::HashAlgorithm::SHA256)
                -> pgp::packet::signature::subpacket::Subpacket
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
        } @ { map() -> pgp::packet::Key::<_, _> }

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
        } @ { map() -> pgp::packet::Key::<_, _> }

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
        } @ {
            map__parse(pgp::types::PublicKeyAlgorithm::RSAEncryptSign)
                -> pgp::crypto::mpi::PublicKey
        }

        ecdh {
            pgp::crypto::mpi::PublicKey::ECDH {
                curve: pgp::crypto::Curve::Cv25519,
                q: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                hash: pgp::crypto::HashAlgorithm::SHA256,
                sym: pgp::crypto::SymmetricAlgorithm::AES128,
            } => 8 @ Ecdh
        } @ {
            map__parse(pgp::types::PublicKeyAlgorithm::ECDH)
                -> pgp::crypto::mpi::PublicKey
        }

        eddsa_legacy {
            pgp::crypto::mpi::PublicKey::EdDSA {
                curve: pgp::crypto::Curve::Ed25519,
                q: pgp::crypto::mpi::MPI::new(&[1, 2, 3]),
            } => 4 @ EdDsaLegacy
        } @ {
            map__parse(pgp::types::PublicKeyAlgorithm::EdDSA)
                -> pgp::crypto::mpi::PublicKey
        }

        x25519 {
            pgp::crypto::mpi::PublicKey::X25519 {
                u: [0u8; 32],
            } => 1 @ X25519
        } @ {
            map__parse(pgp::types::PublicKeyAlgorithm::X25519)
                -> pgp::crypto::mpi::PublicKey
        }

        ed25519 {
            pgp::crypto::mpi::PublicKey::Ed25519 {
                a: [0u8; 32],
            } => 1 @ Ed25519
        } @ {
            map__parse(pgp::types::PublicKeyAlgorithm::Ed25519)
                -> pgp::crypto::mpi::PublicKey
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
