// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED},
    parsers::{parse_i64, parse_u32, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError, EncodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcQdiscTaprio {}

impl TcQdiscTaprio {
    pub(crate) const KIND: &'static str = "taprio";
}

const TCA_TAPRIO_ATTR_PRIOMAP: u16 = 1;
const TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST: u16 = 2;
const TCA_TAPRIO_ATTR_SCHED_BASE_TIME: u16 = 3;
const TCA_TAPRIO_ATTR_SCHED_CLOCKID: u16 = 5;
const TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME: u16 = 8;
const TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION: u16 = 9;
const TCA_TAPRIO_ATTR_FLAGS: u16 = 10;
const TCA_TAPRIO_ATTR_TXTIME_DELAY: u16 = 11;
const TCA_TAPRIO_ATTR_TC_ENTRY: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcQdiscTaprioOption {
    ClockId(u32),
    Flags(u32),
    Priomap(TcPriomap),
    TxtimeDelay(u32),
    Basetime(i64),
    Cycletime(i64),
    CycletimeExtension(i64),
    Tc(Vec<TaprioTcEntry>),
    Schedule(Vec<TaprioScheduleEntry>),
    Other(DefaultNla),
}

impl Nla for TcQdiscTaprioOption {
    fn value_len(&self) -> usize {
        match self {
            Self::ClockId(_) | Self::Flags(_) | Self::TxtimeDelay(_) => 4,
            Self::Basetime(_)
            | Self::Cycletime(_)
            | Self::CycletimeExtension(_) => 8,
            Self::Priomap(v) => v.buffer_len(),
            Self::Tc(nlas) => nlas.as_slice().buffer_len(),
            Self::Schedule(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::ClockId(d) | Self::Flags(d) | Self::TxtimeDelay(d) => {
                NativeEndian::write_u32(buffer, *d)
            }
            Self::Basetime(d)
            | Self::Cycletime(d)
            | Self::CycletimeExtension(d) => {
                NativeEndian::write_i64(buffer, *d)
            }
            Self::Priomap(p) => p.emit(buffer),
            Self::Tc(nlas) => nlas.as_slice().emit(buffer),
            Self::Schedule(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ClockId(_) => TCA_TAPRIO_ATTR_SCHED_CLOCKID,
            Self::Flags(_) => TCA_TAPRIO_ATTR_FLAGS,
            Self::Priomap(_) => TCA_TAPRIO_ATTR_PRIOMAP,
            Self::TxtimeDelay(_) => TCA_TAPRIO_ATTR_TXTIME_DELAY,
            Self::Basetime(_) => TCA_TAPRIO_ATTR_SCHED_BASE_TIME,
            Self::Cycletime(_) => TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME,
            Self::CycletimeExtension(_) => {
                TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION
            }
            Self::Tc(_) => TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED,
            Self::Schedule(_) => {
                TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST | NLA_F_NESTED
            }
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcQdiscTaprioOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_TAPRIO_ATTR_SCHED_CLOCKID => Self::ClockId(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_SCHED_CLOCKID")?,
            ),
            TCA_TAPRIO_ATTR_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_SCHED_FLAGS")?,
            ),
            TCA_TAPRIO_ATTR_PRIOMAP => Self::Priomap(TcPriomap::parse(
                &TcPriomapBuffer::new_checked(payload)?,
            )?),
            TCA_TAPRIO_ATTR_TXTIME_DELAY => Self::TxtimeDelay(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_TXTIME_DELAY")?,
            ),
            TCA_TAPRIO_ATTR_SCHED_BASE_TIME => Self::Basetime(
                parse_i64(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_SCHED_BASE_TIME")?,
            ),
            TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME => Self::Cycletime(
                parse_i64(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME")?,
            ),
            TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION => Self::CycletimeExtension(
                parse_i64(payload)
                    .context("failed to parse TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION")?,
            ),
            TCA_TAPRIO_ATTR_TC_ENTRY => {
                let mut v = Vec::new();
                let err = "failed to parse TCA_TAPRIO_ATTR_TC_ENTRY";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed =
                        TaprioTcEntry::parse(nla).context(err)?;
                    v.push(parsed);
                }
                Self::Tc(v)
            }
            TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST => {
                let mut v = Vec::new();
                let err = "failed to parse TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed =
                        TaprioScheduleEntry::parse(nla).context(err)?;
                    v.push(parsed);
                }
                Self::Schedule(v)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse u32 nla")?,
            ),
        })
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcPriomap {
    pub num_tc: u8,
    pub prio_tc_map: [u8; 16],
    pub hw: u8,
    pub count: [u16; 16],
    pub offset: [u16; 16],
}

impl TcPriomap {
    pub(crate) const BUF_LEN: usize = 82;

    pub fn from_parts(num_tc: u8, prio_tc_map: [u8; 16], hw: u8, count: [u16; 16], offset: [u16; 16]) -> Self {
        Self {
            num_tc,
            prio_tc_map,
            hw,
            count,
            offset,
        }
    }
}

buffer!(TcPriomapBuffer(TcPriomap::BUF_LEN) {
    num_tc: (u8, 0),
    prio_tc_map: (slice, 1..17),
    hw: (u8, 17),
    count: (slice, 18..50),
    offset: (slice, 50..82),
});

impl Emitable for TcPriomap {
    fn buffer_len(&self) -> usize {
        Self::BUF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = TcPriomapBuffer::new(buffer);
        packet.set_num_tc(self.num_tc);
        packet.prio_tc_map_mut().copy_from_slice(&self.prio_tc_map);
        packet.set_hw(self.hw);

        for (chunk, value) in packet
            .count_mut()
            .chunks_exact_mut(2)
            .zip(self.count.iter())
        {
            NativeEndian::write_u16(chunk, *value);
        }

        for (chunk, value) in packet
            .offset_mut()
            .chunks_exact_mut(2)
            .zip(self.offset.iter())
        {
            NativeEndian::write_u16(chunk, *value);
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<TcPriomapBuffer<&'a T>>
    for TcPriomap
{
    fn parse(buf: &TcPriomapBuffer<&T>) -> Result<Self, DecodeError> {
        let mut count: [u16; 16] = [0; 16];
        for (chunk, value) in buf.count().chunks_exact(2).zip(count.iter_mut())
        {
            *value = NativeEndian::read_u16(chunk);
        }

        let mut offset: [u16; 16] = [0; 16];
        for (chunk, value) in
            buf.offset().chunks_exact(2).zip(offset.iter_mut())
        {
            *value = NativeEndian::read_u16(chunk);
        }

        Ok(Self {
            num_tc: buf.num_tc(),
            prio_tc_map: buf.prio_tc_map().try_into().map_err(|_| {
                DecodeError::from("Invalid length of prio_tc_map")
            })?,
            hw: buf.hw(),
            count,
            offset,
        })
    }
}

const TCA_TAPRIO_TC_ENTRY_INDEX: u16 = 1;
const TCA_TAPRIO_TC_ENTRY_MAX_SDU: u16 = 2;
const TCA_TAPRIO_TC_ENTRY_FP: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TaprioTcEntry {
    Index(u32),
    MaxSdu(u32),
    Fp(u32),
    Other(DefaultNla),
}

impl TaprioTcEntry {
    pub fn fp_from_char(c: char) -> Result<Self, EncodeError> {
        if c == 'E' {
            Ok(Self::Fp(1))
        } else if c == 'P' {
            Ok(Self::Fp(2))
        } else {
            Err(EncodeError::from(
                "Currently, only E and P are valid for FP",
            ))
        }
    }
}

impl Nla for TaprioTcEntry {
    fn value_len(&self) -> usize {
        match self {
            Self::Index(_) | Self::MaxSdu(_) | Self::Fp(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Index(d) | Self::MaxSdu(d) | Self::Fp(d) => {
                NativeEndian::write_u32(buffer, *d)
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Index(_) => TCA_TAPRIO_TC_ENTRY_INDEX,
            Self::MaxSdu(_) => TCA_TAPRIO_TC_ENTRY_MAX_SDU,
            Self::Fp(_) => TCA_TAPRIO_TC_ENTRY_FP,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TaprioTcEntry
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_TAPRIO_TC_ENTRY_INDEX => Self::Index(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_TC_ENTRY_INDEX")?,
            ),
            TCA_TAPRIO_TC_ENTRY_MAX_SDU => Self::MaxSdu(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_TC_ENTRY_MAX_SDU")?,
            ),
            TCA_TAPRIO_TC_ENTRY_FP => Self::Fp(
                parse_u32(payload)
                    .context("failed to parse TCA_TAPRIO_TC_ENTRY_FP")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse u32 nla")?,
            ),
        })
    }
}

const TCA_TAPRIO_SCHED_ENTRY: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TaprioScheduleEntry {
    Entry(Vec<TaprioScheduleEntryItem>),
    Other(DefaultNla),
}

impl Nla for TaprioScheduleEntry {
    fn value_len(&self) -> usize {
        match self {
            Self::Entry(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Entry(p) => p.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Entry(_) => TCA_TAPRIO_SCHED_ENTRY,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TaprioScheduleEntry
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_TAPRIO_SCHED_ENTRY => {
                let mut v = Vec::new();
                let err = "failed to parse TCA_TAPRIO_SCHED_ENTRY";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed =
                        TaprioScheduleEntryItem::parse(nla).context(err)?;
                    v.push(parsed);
                }
                Self::Entry(v)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse u32 nla")?,
            ),
        })
    }
}

const TCA_TAPRIO_SCHED_ENTRY_CMD: u16 = 2;
const TCA_TAPRIO_SCHED_ENTRY_GATE_MASK: u16 = 3;
const TCA_TAPRIO_SCHED_ENTRY_INTERVAL: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TaprioScheduleEntryItem {
    Cmd(u8),
    GateMask(u32),
    Interval(u32),
    Other(DefaultNla),
}

impl TaprioScheduleEntryItem {
    pub fn cmd_from_char(c: char) -> Result<Self, EncodeError> {
        if c == 'S' {
            Ok(Self::Cmd(0))
        } else {
            Err(EncodeError::from("Currently, only S is valid as command"))
        }
    }
}

impl Nla for TaprioScheduleEntryItem {
    fn value_len(&self) -> usize {
        match self {
            Self::Cmd(_) => 1,
            Self::GateMask(_) | Self::Interval(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Cmd(d) => buffer[0] = *d,
            Self::GateMask(d) | Self::Interval(d) => {
                NativeEndian::write_u32(buffer, *d)
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Cmd(_) => TCA_TAPRIO_SCHED_ENTRY_CMD,
            Self::GateMask(_) => TCA_TAPRIO_SCHED_ENTRY_GATE_MASK,
            Self::Interval(_) => TCA_TAPRIO_SCHED_ENTRY_INTERVAL,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TaprioScheduleEntryItem
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_TAPRIO_SCHED_ENTRY_CMD => Self::Cmd(
                parse_u8(payload)
                    .context("failed to parse TCA_TAPRIO_SCHED_ENTRY_CMD")?,
            ),
            TCA_TAPRIO_SCHED_ENTRY_GATE_MASK => {
                Self::GateMask(parse_u32(payload).context(
                    "failed to parse TCA_TAPRIO_SCHED_ENTRY_GATE_MASK",
                )?)
            }
            TCA_TAPRIO_SCHED_ENTRY_INTERVAL => {
                Self::Interval(parse_u32(payload).context(
                    "failed to parse TCA_TAPRIO_SCHED_ENTRY_INTERVAL",
                )?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse u32 nla")?,
            ),
        })
    }
}
