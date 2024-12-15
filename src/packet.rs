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
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
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

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn protocol_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::header::PRC_VER.start]
    }

    pub fn inverse_protocol_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::header::IPC_VER.start]
    }

    pub fn payload_type(&self) -> PayloadTypeCode {
        let data = self.buffer.as_ref();
        match PayloadTypeCode::from_u16(NetworkEndian::read_u16(&data[field::header::TYPE])) {
            Some(payload_type) => payload_type,
            None => PayloadTypeCode::GenericDoIPHeaderNegativeResponse,
        }
    }

    pub fn payload_length(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::header::PAYLOAD_LENGTH]) as usize
    }

    pub fn payload_range(&self) -> core::ops::Range<usize> {
        field::header::TYPE.start..field::header::PAYLOAD_LENGTH.end + self.payload_length()
    }

    pub fn payload_content_length(&self) -> usize {
        self.payload_length()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::header::PRC_VER.start] = value;
    }

    pub fn set_inverse_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::header::IPC_VER.start] = value;
    }

    pub fn set_payload_type(&mut self, value: PayloadTypeCode) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::header::TYPE], value as u16);
    }

    pub fn set_payload_length(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::header::PAYLOAD_LENGTH], value as u32);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::header::PAYLOAD_LENGTH.end
            ..field::header::PAYLOAD_LENGTH.end + self.payload_length()]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Returns a mutable reference to the payload.
    #[inline]
    pub fn payload(&mut self) -> &mut [u8] {
        let payload_range = self.payload_range();
        let data = self.buffer.as_mut();

        &mut data[payload_range]
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
