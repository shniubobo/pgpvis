//! Utility structs to convert from [`sequoia_openpgp`]'s data structures into
//! our own ones in [`packet`](crate::packet).

use std::result::Result as StdResult;

use sequoia_openpgp::{
    self as pgp,
    parse::{map::Field as PgpField, PacketParser},
};

use crate::error::*;
use crate::packet::*;

/// Intermediate struct to convert [`PacketParser`] into [`Span<AnyPacket>`].
pub(crate) struct IntermediatePacket<'context, 'packet> {
    context: &'context mut Context,
    spans: Vec<PgpField<'packet>>,
    header: &'packet pgp::packet::Header,
    body: &'packet pgp::Packet,
}

impl<'c, 'p> IntermediatePacket<'c, 'p> {
    pub fn new(context: &'c mut Context, parser: &'p PacketParser) -> IntermediatePacket<'c, 'p> {
        let spans = parser.map().unwrap().iter().collect();
        let header = parser.header();
        let body = &parser.packet;
        Self {
            context,
            spans,
            header,
            body,
        }
    }
}

impl TryFrom<IntermediatePacket<'_, '_>> for Span<AnyPacket> {
    type Error = Error;

    fn try_from(mut value: IntermediatePacket) -> StdResult<Self, Self::Error> {
        value.convert_any_packet()
    }
}

impl IntermediatePacket<'_, '_> {
    const CTB_IDX: usize = 0;
    const LENGTH_IDX: usize = 1;
    const BODY_IDX: usize = 2;

    fn convert_any_packet(&mut self) -> Result<Span<AnyPacket>> {
        let offset = self.context.offset();
        let inner = match self.body {
            pgp::Packet::UserID(user_id) => AnyPacket::UserId(Packet {
                header: self.convert_header()?,
                body: self.convert_user_id(user_id)?,
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
        let (offset, length) = self.advance_offset(Self::CTB_IDX)?;
        let ctb = self.header.ctb().into();

        Ok(Span::new(offset, length, ctb))
    }

    fn convert_length<L>(&mut self) -> Result<Span<L>>
    where
        L: for<'a> TryFrom<&'a pgp::packet::Header, Error = Error> + Length,
    {
        let (offset, length) = self.advance_offset(Self::LENGTH_IDX)?;
        let packet_length = self.header.try_into()?;

        Ok(Span::new(offset, length, packet_length))
    }

    fn convert_user_id(&mut self, user_id: &pgp::packet::UserID) -> Result<Span<Body<UserId>>> {
        let (offset, length) = self.advance_offset(Self::BODY_IDX)?;
        let user_id: UserId = Span::new(offset, length, user_id).into();
        let body = user_id.into();

        Ok(Span::new(offset, length, body))
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
