//! Packet module
//!
//! This module contains the `Packet` type, which is a read/write wrapper around a DoIP packet buffer.

use crate::error::Error;
use crate::field;
use crate::payload::PayloadTypeCode;
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// A read/write wrapper around a DoIP packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Creates a new DoIP packet without checking the buffer length.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Creates a new DoIP packet, checking the buffer length.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        match packet.check_len() {
            Ok(_) => Ok(packet),
            Err(_) => Err(Error),
        }
    }

    /// Checks if the buffer is long enough to contain a valid DoIP packet.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::header::LENGTH {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Returns a reference to the inner buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns the protocol version.
    pub fn protocol_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::header::PRC_VER.start]
    }

    /// Returns the inverse protocol version.
    pub fn inverse_protocol_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::header::IPC_VER.start]
    }

    /// Returns the payload type.
    pub fn payload_type(&self) -> PayloadTypeCode {
        let data = self.buffer.as_ref();
        match PayloadTypeCode::from_u16(NetworkEndian::read_u16(&data[field::header::TYPE])) {
            Some(payload_type) => payload_type,
            None => PayloadTypeCode::GenericDoIPHeaderNegativeResponse,
        }
    }

    /// Returns the length of the payload, excluding payload type and length.
    pub fn payload_length(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::header::PAYLOAD_LENGTH]) as usize
    }

    /// Returns the range of the payload, including payload type and length.
    pub fn payload_range(&self) -> core::ops::Range<usize> {
        field::header::TYPE.start..field::header::PAYLOAD_LENGTH.end + self.payload_length()
    }

    /// Returns the length of the payload content, excluding payload type and length.
    pub fn payload_content_range(&self) -> core::ops::Range<usize> {
        field::header::PAYLOAD_LENGTH.end..field::header::PAYLOAD_LENGTH.end + self.payload_length()
    }

    /// Returns the length of the payload content.
    pub fn payload_content_length(&self) -> usize {
        self.payload_length()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the protocol version.
    pub fn set_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::header::PRC_VER.start] = value;
    }

    /// Sets the inverse protocol version.
    pub fn set_inverse_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::header::IPC_VER.start] = value;
    }

    /// Sets the payload type.
    pub fn set_payload_type(&mut self, value: PayloadTypeCode) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::header::TYPE], value as u16);
    }

    /// Sets the payload length.
    pub fn set_payload_length(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::header::PAYLOAD_LENGTH], value as u32);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Returns a reference to the payload, including payload type and length.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let payload_range = self.payload_range();
        let data = self.buffer.as_ref();

        &data[payload_range]
    }

    /// Returns a reference to the payload content, excluding payload type and length.
    #[inline]
    pub fn payload_content(&self) -> &'a [u8] {
        let payload_range = self.payload_content_range();
        let data = self.buffer.as_ref();

        &data[payload_range]
    }

    #[inline]
    pub fn message(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[..field::header::PAYLOAD_LENGTH.end + self.payload_length()]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Returns a mutable reference to the payload, including payload type and length.
    #[inline]
    pub fn payload(&mut self) -> &mut [u8] {
        let payload_range = self.payload_range();
        let data = self.buffer.as_mut();

        &mut data[payload_range]
    }

    /// Returns a mutable reference to the payload content, excluding payload type and length.
    #[inline]
    pub fn payload_content(&mut self) -> &mut [u8] {
        let payload_range = self.payload_content_range();
        let data = self.buffer.as_mut();

        &mut data[payload_range]
    }

    #[inline]
    pub fn message(&mut self) -> &mut [u8] {
        let payload_length = self.payload_length();
        let data = self.buffer.as_mut();
        &mut data[..field::header::PAYLOAD_LENGTH.end + payload_length]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    /// Formats the packet as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DoIP packet: protocol_version={}, inverse_protocol_version={}, payload_type={}, payload_length={}",
            self.protocol_version(),
            self.inverse_protocol_version(),
            self.payload_type(),
            self.payload_length(),
        )
    }
}
