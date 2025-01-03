//! Utility structs to convert from [`sequoia_openpgp`]'s data structures into
//! our own ones in [`packet`](crate::packet).

use std::result::Result as StdResult;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sequoia_openpgp::{self as pgp, packet::key as pgp_key, parse::PacketParser};

use crate::error::*;
use crate::packet::*;

/// Intermediate struct to convert [`PacketParser`] into [`Span<AnyPacket>`].
pub(crate) struct Converter<'context, 'packet> {
    context: &'context mut Context,
    spans: Vec<pgp::parse::map::Field<'packet>>,
    header: &'packet pgp::packet::Header,
    body: &'packet pgp::Packet,
    next_field_index: usize,
}

impl<'c, 'p> Converter<'c, 'p> {
    pub fn new(context: &'c mut Context, parser: &'p PacketParser) -> Converter<'c, 'p> {
        let spans = parser.map().unwrap().iter().collect();
        let header = parser.header();
        let body = &parser.packet;
        Self {
            context,
            spans,
            header,
            body,
            next_field_index: 0,
        }
    }

    pub fn convert(mut self) -> Result<Span<AnyPacket>> {
        self.convert_any_packet()
    }
}

impl Converter<'_, '_> {
    fn convert_any_packet(&mut self) -> Result<Span<AnyPacket>> {
        let offset = self.context.offset();
        let inner = match self.body {
            pgp::Packet::PublicKey(public_key) => AnyPacket::PublicKey(Packet {
                header: self.convert_header()?,
                body: self.convert_public_key(public_key)?,
            }),
            pgp::Packet::UserID(user_id) => AnyPacket::UserId(Packet {
                header: self.convert_header()?,
                body: self.convert_user_id(user_id)?,
            }),
            pgp::Packet::PublicSubkey(public_subkey) => AnyPacket::PublicSubkey(Packet {
                header: self.convert_header()?,
                body: self.convert_public_subkey(public_subkey)?,
            }),
            unknown_packet => {
                return Err(Error::UnknownPacket {
                    type_id: unknown_packet.tag().into(),
                });
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
            match self.header.ctb() {
                pgp::packet::header::CTB::New(_) => Header::OpenPgp {
                    ctb: self.convert_ctb()?,
                    length: self.convert_length()?,
                },
                pgp::packet::header::CTB::Old(_) => Header::Legacy {
                    ctb: self.convert_ctb()?,
                    length: self.convert_length()?,
                },
            }
        };
        let length = self.context.offset() - offset;

        Ok(Span::new(offset, length, header))
    }

    // TODO: Generate the following methods with macros.

    fn convert_ctb<C, P>(&mut self) -> Result<Span<C>>
    where
        C: for<'a> From<&'a pgp::packet::header::CTB> + Into<Ctb<P>>,
        P: PacketType,
    {
        let span = self.next_span()?;
        let ctb = self.header.ctb().into();

        Ok(span.replace_with(ctb))
    }

    fn convert_length<L>(&mut self) -> Result<Span<L>>
    where
        L: for<'a> TryFrom<&'a pgp::packet::Header, Error = Error> + Length,
    {
        let span = self.next_span()?;
        let packet_length = self.header.try_into()?;

        Ok(span.replace_with(packet_length))
    }

    fn convert_user_id(&mut self, user_id: &pgp::packet::UserID) -> Result<Span<Body<UserId>>> {
        let span = self.next_span()?;
        let user_id: UserId = span.replace_with(user_id).into();
        let body = user_id.into();

        Ok(span.replace_with(body))
    }

    fn convert_public_key(
        &mut self,
        public_key: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>,
    ) -> Result<Span<Body<PublicKey>>> {
        let public_key_span = PublicKey::convert(public_key, self)?;
        let body_span = public_key_span.transpose();
        Ok(body_span)
    }

    fn convert_public_subkey(
        &mut self,
        public_key: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>,
    ) -> Result<Span<Body<PublicSubkey>>> {
        let public_key_span = PublicSubkey::convert(public_key, self)?;
        let body_span = public_key_span.transpose();
        Ok(body_span)
    }

    fn next_span(&mut self) -> Result<Span<()>> {
        let field = self.next_field_index();
        let (offset, length) = self.advance_offset(field)?;
        Ok(Span::new(offset, length, ()))
    }

    fn next_field_index(&mut self) -> usize {
        let index = self.next_field_index;
        self.next_field_index += 1;
        index
    }

    fn offset(&self) -> usize {
        self.context.offset()
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

impl TryFrom<&pgp::packet::Header> for OpenPgpLength {
    type Error = Error;

    fn try_from(header: &pgp::packet::Header) -> StdResult<Self, Self::Error> {
        if let pgp::packet::header::CTB::Old(_) = header.ctb() {
            return Err(Error::WrongFormat {
                expected: "OpenPGP".to_string(),
                got: "Legacy".to_string(),
            });
        };

        use pgp::packet::header::BodyLength as PgpBodyLength;
        let length = match *header.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(length) => Self::Partial(length),
            PgpBodyLength::Indeterminate => unreachable!(),
        };
        Ok(length)
    }
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

        use pgp::packet::header::BodyLength as PgpBodyLength;
        let length = match *header.length() {
            PgpBodyLength::Full(length) => Self::Full(length),
            PgpBodyLength::Partial(_) => unreachable!(),
            PgpBodyLength::Indeterminate => Self::Indeterminate,
        };
        Ok(length)
    }
}

trait Convert<F> {
    fn convert(from: &F, converter: &mut Converter) -> Result<Span<Self>>
    where
        Self: Sized;
}

impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>> for PublicKey {
    fn convert(
        from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::PrimaryRole>,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        if let pgp::packet::Key::V4(key) = from {
            let offset = converter.offset();

            let version_span = converter.next_span()?;
            let creation_time = Time::convert(from, converter)?;
            let algorithm_span = converter.next_span()?;
            let ret = match key.pk_algo() {
                pgp::types::PublicKeyAlgorithm::RSAEncryptSign => {
                    let key_material = RsaEncryptSign::convert(from.mpis(), converter)?;
                    Self::Version4RsaEncryptSign(PublicVersion4::new(
                        version_span,
                        creation_time,
                        algorithm_span,
                        key_material,
                    ))
                }
                _ => return Err(Error::Unimplemented),
            };

            let length = converter.offset() - offset;

            return Ok(Span::new(offset, length, ret));
        };
        Err(Error::Unimplemented)
    }
}

impl Convert<pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>> for PublicSubkey {
    fn convert(
        from: &pgp::packet::Key<pgp_key::PublicParts, pgp_key::SubordinateRole>,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        if let pgp::packet::Key::V4(key) = from {
            let offset = converter.offset();

            let version_span = converter.next_span()?;
            let creation_time = Time::convert(from, converter)?;
            let algorithm_span = converter.next_span()?;
            let ret = match key.pk_algo() {
                pgp::types::PublicKeyAlgorithm::RSAEncryptSign => {
                    let key_material = RsaEncryptSign::convert(from.mpis(), converter)?;
                    Self::Version4RsaEncryptSign(PublicVersion4::new(
                        version_span,
                        creation_time,
                        algorithm_span,
                        key_material,
                    ))
                }
                _ => return Err(Error::Unimplemented),
            };

            let length = converter.offset() - offset;

            return Ok(Span::new(offset, length, ret));
        };
        Err(Error::Unimplemented)
    }
}

impl<R> Convert<pgp::packet::Key<pgp_key::PublicParts, R>> for Time
where
    R: pgp_key::KeyRole,
{
    fn convert(
        from: &pgp::packet::Key<pgp_key::PublicParts, R>,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        let span = converter.next_span()?;
        let creation_time = from.creation_time().try_into()?;
        Ok(span.replace_with(creation_time))
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
    fn convert(
        from: &pgp::crypto::mpi::PublicKey,
        converter: &mut Converter,
    ) -> Result<Span<Self>> {
        if let pgp::crypto::mpi::PublicKey::RSA { e, n } = from {
            let offset = converter.offset();

            let n = Mpi::convert(n, converter)?;
            let e = Mpi::convert(e, converter)?;

            let length = converter.offset() - offset;

            let ret = RsaEncryptSign::new(n, e);
            return Ok(Span::new(offset, length, ret));
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
    fn convert(from: &pgp::crypto::mpi::MPI, converter: &mut Converter) -> Result<Span<Self>> {
        let offset = converter.offset();

        let length_field_span = converter.next_span()?;
        // As per RFC 9580, the length is reprensented by two octets only, so
        // casting to `u16` is safe.
        let length_field = length_field_span.replace_with(from.bits() as u16);
        let integers_span = converter.next_span()?;
        let integers = integers_span.replace_with(from.value().to_vec());
        let mpi = Mpi::new(length_field, integers);

        let span_length = converter.offset() - offset;

        Ok(Span {
            offset,
            length: span_length,
            inner: mpi,
        })
    }
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
