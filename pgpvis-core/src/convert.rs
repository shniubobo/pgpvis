//! Utility structs to convert from [`sequoia_openpgp`]'s data structures into
//! our own ones in [`packet`](crate::packet).

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
                return Err(Error::UnknownPacket {
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
        Err(Error::Unimplemented)
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

impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>> for PublicKey {
    fn convert(
        from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>,
        converter: &mut Converter,
    ) -> Result<Self> {
        if let pgp::packet::Key::V4(key) = from {
            let version_span = converter.next_span()?;
            let creation_time = Time::convert_spanned(from, converter)?;
            let algorithm_span = converter.next_span()?;
            let key_id = from.keyid().to_hex();
            let ret = match key.pk_algo() {
                pgp::types::PublicKeyAlgorithm::RSAEncryptSign => {
                    let key_material = RsaEncryptSign::convert_spanned(from.mpis(), converter)?;
                    Self::Version4RsaEncryptSign(PublicVersion4::new(
                        version_span,
                        creation_time,
                        algorithm_span,
                        key_material,
                        key_id,
                    ))
                }
                _ => return Err(Error::Unimplemented),
            };
            return Ok(ret);
        };
        Err(Error::Unimplemented)
    }
}

impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>> for PublicSubkey {
    fn convert(
        from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>,
        converter: &mut Converter,
    ) -> Result<Self> {
        // Exactly the same as `PublicKey`'s implementation; maybe should be deduplicated.
        if let pgp::packet::Key::V4(key) = from {
            let version_span = converter.next_span()?;
            let creation_time = Time::convert_spanned(from, converter)?;
            let algorithm_span = converter.next_span()?;
            let key_id = from.keyid().to_hex();
            let ret = match key.pk_algo() {
                pgp::types::PublicKeyAlgorithm::RSAEncryptSign => {
                    let key_material = RsaEncryptSign::convert_spanned(from.mpis(), converter)?;
                    Self::Version4RsaEncryptSign(PublicVersion4::new(
                        version_span,
                        creation_time,
                        algorithm_span,
                        key_material,
                        key_id,
                    ))
                }
                _ => return Err(Error::Unimplemented),
            };
            return Ok(ret);
        };
        Err(Error::Unimplemented)
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
        if since_epoch > u32::MAX as u64 {
            return Err(Error::TimeOverflow { secs: since_epoch });
        }
        Ok(Self::new(since_epoch as u32))
    }
}

impl Convert<pgp::crypto::mpi::PublicKey> for RsaEncryptSign {
    fn convert(from: &pgp::crypto::mpi::PublicKey, converter: &mut Converter) -> Result<Self> {
        if let pgp::crypto::mpi::PublicKey::RSA { e, n } = from {
            let n = Mpi::convert_spanned(n, converter)?;
            let e = Mpi::convert_spanned(e, converter)?;
            return Ok(RsaEncryptSign::new(n, e));
        }

        Err(Error::WrongPublicKeyAlgorithm {
            expected: Self::ID,
            got: from
                .algo()
                // Returning 0 since we cannot get the exact id here.
                .unwrap_or(pgp::types::PublicKeyAlgorithm::Unknown(0)),
        })
    }
}

impl Convert<pgp::crypto::mpi::MPI> for Mpi {
    fn convert(from: &pgp::crypto::mpi::MPI, converter: &mut Converter) -> Result<Self> {
        // As per RFC 9580, the length is reprensented by two octets only, so
        // casting to `u16` is safe.
        let length_field_span = converter.next_span_with(from.bits() as u16)?;
        let integers_span = converter.next_span_with(from.value().to_vec())?;
        Ok(Mpi::new(length_field_span, integers_span))
    }
}

impl Convert<pgp::packet::UserID> for UserId {
    fn convert(from: &pgp::packet::UserID, converter: &mut Converter) -> Result<Self> {
        let user_id_field = String::from_utf8_lossy(from.value()).to_string();
        let span = converter.next_span_with(user_id_field)?;
        Ok(UserId::new(span))
    }
}
