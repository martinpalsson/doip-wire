use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

/// A DoIP packet error.
#[derive(PartialEq, Debug)]
pub struct Error;

/// A read/write wrapper around a DoIP packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

pub type Result<T> = core::result::Result<T, Error>;

// Format of the DoIP header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Header syncronization pattern                      |
// |       Protocol version        |       Inverse protocol version      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              Payload                                |
// |  Payload type code  |  Payload length  |    Payload type content    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
mod field {
    #![allow(non_snake_case)]

    pub type Field = ::core::ops::Range<usize>;
    pub mod header {
        use crate::field::Field;
        pub const PRC_VER: Field = 0..1;
        pub const IPC_VER: Field = 1..2;
        pub const TYPE: Field = 2..4;
        pub const PAYLOAD_LENGTH: Field = 4..8;

        /// The length of the DoIP header excluding payload.
        pub const LENGTH: usize = IPC_VER.end;
    }

    pub mod payload {
        use crate::field::Field;
        pub const TYPE: Field = 0..2;
        pub const PAYLOAD_LENGTH: Field = 2..6;

        /// Generic DoIP Header Negative Acknowledgement
        pub mod gdhna {
            pub const LENGTH: usize = 0;
        }

        /// Vehicle Identification Request
        pub mod vir {
            pub const LENGTH: usize = 0;
        }

        /// Vehicle Identification Request with EID
        pub mod vir_eid {
            use crate::field::Field;
            pub const EID: Field = 0..6;

            pub const LENGTH: usize = 6;
            pub const EID_LENGTH: usize = 6;
        }

        /// Vehicle Identification Request with VIN
        pub mod vir_vin {
            use crate::field::Field;
            pub const VIN: Field = 0..17;

            pub const LENGTH: usize = 17;
            pub const VIN_LENGTH: usize = 17;
        }

        /// Vehicle Announce Message / Vehicle Identification Response
        pub mod vam {
            use crate::field::Field;
            pub const VIN: Field = 0..17;
            pub const LA: Field = 17..19;
            pub const EID: Field = 19..25;
            pub const GID: Field = 25..31;
            pub const FTA: Field = 31..32;
            pub const GSS: Field = 32..33;

            pub const LENGTH: usize = 33;
            pub const VIN_LENGTH: usize = 17;
            pub const EID_LENGTH: usize = 6;
            pub const GID_LENGTH: usize = 6;
        }

        /// Routing Activation Request
        pub mod ra_req {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const AT: Field = 2..3;
            pub const ISO_RES: Field = 3..7;
            pub const OEM_RES: Field = 7..11;
            pub const LENGTH: usize = 11;
        }

        /// Routing Activation Response
        pub mod ra_res {
            use crate::field::Field;
            pub const LAT: Field = 0..2;
            pub const LADE: Field = 2..4;
            pub const RCODE: Field = 4..5;
            pub const ISO_RES: Field = 5..9;
            pub const OEM_RES: Field = 9..13;
            pub const LENGTH: usize = 13;
        }

        /// Alive Check Request
        pub mod ac_req {
            pub const LENGTH: usize = 0;
        }

        /// Alive Check Response
        pub mod ac_res {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const LENGTH: usize = 2;
        }

        /// DoIP Entity Status Request
        pub mod des_req {
            pub const LENGTH: usize = 0;
        }

        // DoIP Entity Status Response
        pub mod des_res {
            use crate::field::Field;
            pub const NT: Field = 0..1;
            pub const MOS: Field = 1..2;
            pub const COS: Field = 2..3;
            pub const MDS: Field = 3..7;
            pub const LENGTH: usize = 7;
        }

        /// Diagnostic Power Mode Information Request
        pub mod dpmi_req {
            pub const LENGTH: usize = 0;
        }

        /// Diagnostic Power Mode Information Response
        pub mod dpmi_res {
            use crate::field::Field;
            pub const DPM: Field = 0..1;
            pub const LENGTH: usize = 1;
        }

        /// Diagnostic Message
        pub mod dm {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const TA: Field = 2..4;
            pub const fn DATA(length: usize) -> Field {
                TA.end..TA.end + length
            }
        }

        /// Diagnostic Message Positive/Negative Acknowledgement
        pub mod dm_xack {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const TA: Field = 2..4;
            pub const ACKC: Field = 4..5;
            pub const fn DATA(length: usize) -> Field {
                ACKC.end..ACKC.end + length
            }
        }
    }
}

/// Enum representing the different payload types in the DoIP protocol.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u16)]
pub enum PayloadTypeCode {
    GenericDoIPHeaderNegativeResponse = 0x0000,
    VehicleIdentificationRequest = 0x0001,
    VehicleIdentificationRequestEID = 0x0002,
    VehicleIdentificationRequestVIN = 0x0003,
    VehicleAnnouncementMessage = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DoIPEntityStatusRequest = 0x4001,
    DoIPEntityStatusResponse = 0x4002,
    DiagnosticPowerModeInformationRequest = 0x4003,
    DiagnosticPowerModeInformationResponse = 0x4004,
    DiagnosticMessage = 0x8001,
    DiagnosticMessageAck = 0x8002,
    DiagnosticMessageNack = 0x8003,
}

impl PayloadTypeCode {
    /// Converts a u16 to a PayloadTypeCode.
    ///
    /// # Arguments
    ///
    /// * `value` - A u16 value representing the payload type.
    ///
    /// # Returns
    ///
    /// * `Some(PayloadTypeCode)` - The corresponding PayloadTypeCode if the value is valid.
    /// * `None` - If the value does not correspond to a valid PayloadTypeCode.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(PayloadTypeCode::GenericDoIPHeaderNegativeResponse),
            0x0001 => Some(PayloadTypeCode::VehicleIdentificationRequest),
            0x0002 => Some(PayloadTypeCode::VehicleIdentificationRequestEID),
            0x0003 => Some(PayloadTypeCode::VehicleIdentificationRequestVIN),
            0x0004 => Some(PayloadTypeCode::VehicleAnnouncementMessage),
            0x0005 => Some(PayloadTypeCode::RoutingActivationRequest),
            0x0006 => Some(PayloadTypeCode::RoutingActivationResponse),
            0x0007 => Some(PayloadTypeCode::AliveCheckRequest),
            0x0008 => Some(PayloadTypeCode::AliveCheckResponse),
            0x4001 => Some(PayloadTypeCode::DoIPEntityStatusRequest),
            0x4002 => Some(PayloadTypeCode::DoIPEntityStatusResponse),
            0x4003 => Some(PayloadTypeCode::DiagnosticPowerModeInformationRequest),
            0x4004 => Some(PayloadTypeCode::DiagnosticPowerModeInformationResponse),
            0x8001 => Some(PayloadTypeCode::DiagnosticMessage),
            0x8002 => Some(PayloadTypeCode::DiagnosticMessageAck),
            0x8003 => Some(PayloadTypeCode::DiagnosticMessageNack),
            _ => None,
        }
    }
}

impl fmt::Display for PayloadTypeCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse => {
                write!(f, "Generic DoIP header negative response")
            }
            PayloadTypeCode::VehicleIdentificationRequest => {
                write!(f, "Vehicle identification request")
            }
            PayloadTypeCode::VehicleIdentificationRequestEID => {
                write!(f, "Vehicle identification request with EID")
            }
            PayloadTypeCode::VehicleIdentificationRequestVIN => {
                write!(f, "Vehicle identification request with VIN")
            }
            PayloadTypeCode::VehicleAnnouncementMessage => {
                write!(f, "Vehicle announcement message")
            }
            PayloadTypeCode::RoutingActivationRequest => {
                write!(f, "Routing activation request")
            }
            PayloadTypeCode::RoutingActivationResponse => {
                write!(f, "Routing activation response")
            }
            PayloadTypeCode::AliveCheckRequest => {
                write!(f, "Alive check request")
            }
            PayloadTypeCode::AliveCheckResponse => {
                write!(f, "Alive check response")
            }
            PayloadTypeCode::DoIPEntityStatusRequest => {
                write!(f, "DoIP entity status request")
            }
            PayloadTypeCode::DoIPEntityStatusResponse => {
                write!(f, "DoIP entity status response")
            }
            PayloadTypeCode::DiagnosticPowerModeInformationRequest => {
                write!(f, "Diagnostic power mode information request")
            }
            PayloadTypeCode::DiagnosticPowerModeInformationResponse => {
                write!(f, "Diagnostic power mode information response")
            }
            PayloadTypeCode::DiagnosticMessage => {
                write!(f, "Diagnostic message")
            }
            PayloadTypeCode::DiagnosticMessageAck => {
                write!(f, "Diagnostic message positive acknowledgement")
            }
            PayloadTypeCode::DiagnosticMessageNack => {
                write!(f, "Diagnostic message negative acknowledgement")
            }
        }
    }
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

/// Represents the different types of payloads in the DoIP protocol.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PayloadTypeContent<'a> {
    GenericDoIPHeaderNegativeResponse,
    VehicleIdentificationRequest,
    VehicleIdentificationRequestWithEID {
        eid: &'a [u8; field::payload::vir_eid::EID_LENGTH],
    },
    VehicleIdentificationRequestWithVIN {
        vin: &'a [u8; field::payload::vir_vin::VIN_LENGTH],
    },
    VehicleIdentificationResponseMessage {
        vin: &'a [u8; field::payload::vam::VIN_LENGTH],
        logical_address: u16,
        eid: &'a [u8; field::payload::vam::EID_LENGTH],
        gid: &'a [u8; field::payload::vam::GID_LENGTH],
        further_action: u8,
        gid_sync_status: u8,
    },
    RoutingActivationRequest {
        source_address: u16,
        activation_type: u8,
        iso_reserved: u32,
        oem_specific: u32,
    },
    RoutingActivationResponse {
        logical_address_tester: u16,
        logical_address_doip_entity: u16,
        routing_activation_response_code: u8,
        iso_reserved: u32,
        oem_specific: u32,
    },
    AliveCheckRequest,
    AliveCheckResponse {
        source_address: u16,
    },
    DoIPEntityStatusRequest,
    DoIPEntityStatusResponse {
        node_type: u8,
        max_open_sockets: u8,
        currently_open_sockets: u8,
        max_data_size: u32,
    },
    DiagnosticPowerModeInformationRequest,
    DiagnosticPowerModeInformationResponse {
        diagnostic_power_mode: u8,
    },
    DiagnosticMessage {
        source_address: u16,
        target_address: u16,
        user_data: &'a [u8],
    },
    DiagnosticMessagePositiveAcknowledgement {
        source_address: u16,
        target_address: u16,
        ack_code: u8,
        previous_diagnostic_message: &'a [u8],
    },
    DiagnosticMessageNegativeAcknowledgement {
        source_address: u16,
        target_address: u16,
        nack_code: u8,
        previous_diagnostic_message: &'a [u8],
    },
}

impl<'a> PayloadTypeContent<'a> {
    /// Parses the buffer and returns the corresponding PayloadTypeContent.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A byte slice containing the data to be parsed.
    /// * `payload_type` - The type of payload to be parsed.
    ///
    /// # Returns
    ///
    /// * `Ok((remaining_buffer, payload))` - A tuple containing the remaining buffer and the parsed PayloadTypeContent.
    /// * `Err(Error)` - An error if the buffer is too short or contains invalid data.
    pub fn parse(
        buffer: &'a [u8],
        payload_type: PayloadTypeCode,
        payload_content_length: usize,
    ) -> Result<(&'a [u8], PayloadTypeContent<'a>)> {
        let (length, payload);
        match payload_type {
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse => {
                length = field::payload::gdhna::LENGTH;
                payload = PayloadTypeContent::GenericDoIPHeaderNegativeResponse;
            }
            PayloadTypeCode::VehicleIdentificationRequest => {
                length = field::payload::vir::LENGTH;
                payload = PayloadTypeContent::VehicleIdentificationRequest;
            }
            PayloadTypeCode::VehicleIdentificationRequestEID => {
                if buffer.len() < field::payload::vir_eid::LENGTH {
                    return Err(Error);
                }
                let eid = buffer.get(field::payload::vir_eid::EID).ok_or(Error)?;
                length = field::payload::vir_eid::LENGTH;
                payload = PayloadTypeContent::VehicleIdentificationRequestWithEID {
                    eid: eid.try_into().unwrap(),
                };
            }
            PayloadTypeCode::VehicleIdentificationRequestVIN => {
                if buffer.len() < field::payload::vir_vin::LENGTH {
                    return Err(Error);
                }
                let vin = buffer.get(field::payload::vir_vin::VIN).ok_or(Error)?;
                length = field::payload::vir_vin::LENGTH;
                payload = PayloadTypeContent::VehicleIdentificationRequestWithVIN {
                    vin: vin.try_into().unwrap(),
                };
            }
            PayloadTypeCode::VehicleAnnouncementMessage => {
                if buffer.len() < field::payload::vam::LENGTH {
                    return Err(Error);
                }
                let vin = buffer.get(field::payload::vam::VIN).ok_or(Error)?;
                let logical_address = NetworkEndian::read_u16(&buffer[field::payload::vam::LA]);
                let eid = buffer.get(field::payload::vam::EID).ok_or(Error)?;
                let gid = buffer.get(field::payload::vam::GID).ok_or(Error)?;
                let further_action = buffer[field::payload::vam::FTA.start];
                let gid_sync_status = buffer[field::payload::vam::GSS.start];
                length = field::payload::vam::LENGTH;
                payload = PayloadTypeContent::VehicleIdentificationResponseMessage {
                    vin: vin.try_into().unwrap(),
                    logical_address,
                    eid: eid.try_into().unwrap(),
                    gid: gid.try_into().unwrap(),
                    further_action,
                    gid_sync_status,
                };
            }
            PayloadTypeCode::RoutingActivationRequest => {
                if buffer.len() < field::payload::ra_req::LENGTH {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(&buffer[field::payload::ra_req::SA]);
                let activation_type = buffer[field::payload::ra_req::AT.start];
                let iso_reserved =
                    NetworkEndian::read_u32(&buffer[field::payload::ra_req::ISO_RES]);
                let oem_specific =
                    NetworkEndian::read_u32(&buffer[field::payload::ra_req::OEM_RES]);
                length = field::payload::ra_req::LENGTH;
                payload = PayloadTypeContent::RoutingActivationRequest {
                    source_address,
                    activation_type,
                    iso_reserved,
                    oem_specific,
                };
            }
            PayloadTypeCode::RoutingActivationResponse => {
                if buffer.len() < field::payload::ra_res::LENGTH {
                    return Err(Error);
                }
                let logical_address_tester =
                    NetworkEndian::read_u16(&buffer[field::payload::ra_res::LAT]);
                let logical_address_doip_entity =
                    NetworkEndian::read_u16(&buffer[field::payload::ra_res::LADE]);
                let routing_activation_response_code = buffer[field::payload::ra_res::RCODE.start];
                let iso_reserved =
                    NetworkEndian::read_u32(&buffer[field::payload::ra_res::ISO_RES]);
                let oem_specific =
                    NetworkEndian::read_u32(&buffer[field::payload::ra_res::OEM_RES]);
                length = field::payload::ra_res::LENGTH;
                payload = PayloadTypeContent::RoutingActivationResponse {
                    logical_address_tester,
                    logical_address_doip_entity,
                    routing_activation_response_code,
                    iso_reserved,
                    oem_specific,
                };
            }
            PayloadTypeCode::AliveCheckRequest => {
                length = field::payload::ac_req::LENGTH;
                payload = PayloadTypeContent::AliveCheckRequest;
            }
            PayloadTypeCode::AliveCheckResponse => {
                if buffer.len() < field::payload::ac_res::LENGTH {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(&buffer[field::payload::ac_res::SA]);
                length = field::payload::ac_res::LENGTH;
                payload = PayloadTypeContent::AliveCheckResponse { source_address };
            }
            PayloadTypeCode::DoIPEntityStatusRequest => {
                length = 0;
                payload = PayloadTypeContent::DoIPEntityStatusRequest;
            }
            PayloadTypeCode::DoIPEntityStatusResponse => {
                if buffer.len() < field::payload::des_res::LENGTH {
                    return Err(Error);
                }
                let node_type = buffer[field::payload::des_res::NT.start];
                let max_open_sockets = buffer[field::payload::des_res::MOS.start];
                let currently_open_sockets = buffer[field::payload::des_res::COS.start];
                let max_data_size = NetworkEndian::read_u32(&buffer[field::payload::des_res::MDS]);
                length = field::payload::des_res::LENGTH;
                payload = PayloadTypeContent::DoIPEntityStatusResponse {
                    node_type,
                    max_open_sockets,
                    currently_open_sockets,
                    max_data_size,
                };
            }
            PayloadTypeCode::DiagnosticPowerModeInformationRequest => {
                length = field::payload::dpmi_req::LENGTH;
                payload = PayloadTypeContent::DiagnosticPowerModeInformationRequest;
            }
            PayloadTypeCode::DiagnosticPowerModeInformationResponse => {
                if buffer.len() < field::payload::dpmi_res::LENGTH {
                    return Err(Error);
                }
                let diagnostic_power_mode = buffer[field::payload::dpmi_res::DPM.start];
                length = field::payload::dpmi_res::LENGTH;
                payload = PayloadTypeContent::DiagnosticPowerModeInformationResponse {
                    diagnostic_power_mode,
                };
            }
            PayloadTypeCode::DiagnosticMessage => {
                if buffer.len() < field::payload::dm::DATA(0).end {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(&buffer[field::payload::dm::SA]);
                let target_address = NetworkEndian::read_u16(&buffer[field::payload::dm::TA]);
                length = buffer.len();
                let user_data = &buffer
                    [field::payload::dm::DATA(payload_content_length - field::payload::dm::TA.end)];
                payload = PayloadTypeContent::DiagnosticMessage {
                    source_address,
                    target_address,
                    user_data,
                };
            }
            PayloadTypeCode::DiagnosticMessageAck => {
                if buffer.len() < field::payload::dm_xack::DATA(0).end {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(&buffer[field::payload::dm_xack::SA]);
                let target_address = NetworkEndian::read_u16(&buffer[field::payload::dm_xack::TA]);
                let ack_code = buffer[field::payload::dm_xack::ACKC.start];
                length = buffer.len();
                let previous_diagnostic_message = &buffer[field::payload::dm_xack::DATA(
                    payload_content_length - field::payload::dm_xack::ACKC.end,
                )];
                payload = PayloadTypeContent::DiagnosticMessagePositiveAcknowledgement {
                    source_address,
                    target_address,
                    ack_code,
                    previous_diagnostic_message,
                };
            }
            PayloadTypeCode::DiagnosticMessageNack => {
                if buffer.len() < field::payload::dm_xack::DATA(0).end {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(&buffer[field::payload::dm_xack::SA]);
                let target_address = NetworkEndian::read_u16(&buffer[field::payload::dm_xack::TA]);
                let nack_code = buffer[field::payload::dm_xack::ACKC.start];
                length = buffer.len();
                let previous_diagnostic_message = &buffer[field::payload::dm_xack::DATA(
                    payload_content_length - field::payload::dm_xack::ACKC.end,
                )];
                payload = PayloadTypeContent::DiagnosticMessageNegativeAcknowledgement {
                    source_address,
                    target_address,
                    nack_code,
                    previous_diagnostic_message,
                };
            }
        }
        Ok((&buffer[length..], payload))
    }

    /// Emits the payload into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable byte slice where the payload will be written.
    ///
    /// # Returns
    ///
    /// * The remaining buffer after writing the payload.
    pub fn emit<'b>(&self, buffer: &'b mut [u8], payload_content_length: usize) -> &'b mut [u8] {
        let length;
        match *self {
            PayloadTypeContent::GenericDoIPHeaderNegativeResponse => {
                length = field::payload::gdhna::LENGTH;
            }
            PayloadTypeContent::VehicleIdentificationRequest => {
                length = field::payload::vir::LENGTH;
            }
            PayloadTypeContent::VehicleIdentificationRequestWithEID { eid } => {
                buffer[field::payload::vir_eid::EID].copy_from_slice(eid);
                length = field::payload::vir_eid::LENGTH;
            }
            PayloadTypeContent::VehicleIdentificationRequestWithVIN { vin } => {
                buffer[field::payload::vir_vin::VIN].copy_from_slice(vin);
                length = field::payload::vir_vin::LENGTH;
            }
            PayloadTypeContent::VehicleIdentificationResponseMessage {
                vin,
                logical_address,
                eid,
                gid,
                further_action,
                gid_sync_status,
            } => {
                buffer[field::payload::vam::VIN].copy_from_slice(vin);
                NetworkEndian::write_u16(&mut buffer[field::payload::vam::LA], logical_address);
                buffer[field::payload::vam::EID].copy_from_slice(eid);
                buffer[field::payload::vam::GID].copy_from_slice(gid);
                buffer[field::payload::vam::FTA.start] = further_action;
                buffer[field::payload::vam::GSS.start] = gid_sync_status;
                length = field::payload::vam::LENGTH;
            }
            PayloadTypeContent::RoutingActivationRequest {
                source_address,
                activation_type,
                iso_reserved,
                oem_specific,
            } => {
                NetworkEndian::write_u16(&mut buffer[field::payload::ra_req::SA], source_address);
                buffer[field::payload::ra_req::AT.start] = activation_type;
                NetworkEndian::write_u32(
                    &mut buffer[field::payload::ra_req::ISO_RES],
                    iso_reserved,
                );
                NetworkEndian::write_u32(
                    &mut buffer[field::payload::ra_req::OEM_RES],
                    oem_specific,
                );
                length = field::payload::ra_req::LENGTH;
            }
            PayloadTypeContent::RoutingActivationResponse {
                logical_address_tester,
                logical_address_doip_entity,
                routing_activation_response_code,
                iso_reserved,
                oem_specific,
            } => {
                NetworkEndian::write_u16(
                    &mut buffer[field::payload::ra_res::LAT],
                    logical_address_tester,
                );
                NetworkEndian::write_u16(
                    &mut buffer[field::payload::ra_res::LADE],
                    logical_address_doip_entity,
                );
                buffer[field::payload::ra_res::RCODE.start] = routing_activation_response_code;
                NetworkEndian::write_u32(
                    &mut buffer[field::payload::ra_res::ISO_RES],
                    iso_reserved,
                );
                NetworkEndian::write_u32(
                    &mut buffer[field::payload::ra_res::OEM_RES],
                    oem_specific,
                );
                length = field::payload::ra_res::LENGTH;
            }
            PayloadTypeContent::AliveCheckRequest => {
                length = field::payload::ac_req::LENGTH;
            }
            PayloadTypeContent::AliveCheckResponse { source_address } => {
                NetworkEndian::write_u16(&mut buffer[field::payload::ac_res::SA], source_address);
                length = field::payload::ac_res::LENGTH;
            }
            PayloadTypeContent::DoIPEntityStatusRequest => {
                length = field::payload::des_req::LENGTH;
            }
            PayloadTypeContent::DoIPEntityStatusResponse {
                node_type,
                max_open_sockets,
                currently_open_sockets,
                max_data_size,
            } => {
                buffer[field::payload::des_res::NT.start] = node_type;
                buffer[field::payload::des_res::MOS.start] = max_open_sockets;
                buffer[field::payload::des_res::COS.start] = currently_open_sockets;
                NetworkEndian::write_u32(&mut buffer[field::payload::des_res::MDS], max_data_size);
                length = field::payload::des_res::LENGTH;
            }
            PayloadTypeContent::DiagnosticPowerModeInformationRequest => {
                length = field::payload::dpmi_req::LENGTH;
            }
            PayloadTypeContent::DiagnosticPowerModeInformationResponse {
                diagnostic_power_mode,
            } => {
                buffer[field::payload::dpmi_res::DPM.start] = diagnostic_power_mode;
                length = field::payload::dpmi_res::LENGTH;
            }
            PayloadTypeContent::DiagnosticMessage {
                source_address,
                target_address,
                user_data,
            } => {
                NetworkEndian::write_u16(&mut buffer[field::payload::dm::SA], source_address);
                NetworkEndian::write_u16(&mut buffer[field::payload::dm::TA], target_address);
                let data_range =
                    field::payload::dm::DATA(payload_content_length - field::payload::dm::TA.end);
                length = data_range.end;
                buffer[data_range].copy_from_slice(user_data);
            }
            PayloadTypeContent::DiagnosticMessagePositiveAcknowledgement {
                source_address,
                target_address,
                ack_code,
                previous_diagnostic_message,
            } => {
                NetworkEndian::write_u16(&mut buffer[field::payload::dm_xack::SA], source_address);
                NetworkEndian::write_u16(&mut buffer[field::payload::dm_xack::TA], target_address);
                buffer[field::payload::dm_xack::ACKC.start] = ack_code;
                let prev_diag_msg_len = payload_content_length - field::payload::dm_xack::ACKC.end;
                let data_range = field::payload::dm_xack::DATA(prev_diag_msg_len);
                length = data_range.len();
                buffer[data_range]
                    .copy_from_slice(&previous_diagnostic_message[..prev_diag_msg_len]);
            }
            PayloadTypeContent::DiagnosticMessageNegativeAcknowledgement {
                source_address,
                target_address,
                nack_code,
                previous_diagnostic_message,
            } => {
                NetworkEndian::write_u16(&mut buffer[field::payload::dm_xack::SA], source_address);
                NetworkEndian::write_u16(&mut buffer[field::payload::dm_xack::TA], target_address);
                buffer[field::payload::dm_xack::ACKC.start] = nack_code;
                let prev_diag_msg_len = payload_content_length - field::payload::dm_xack::ACKC.end;
                let data_range = field::payload::dm_xack::DATA(prev_diag_msg_len);
                length = data_range.len();
                buffer[data_range]
                    .copy_from_slice(&previous_diagnostic_message[..prev_diag_msg_len]);
            }
        }
        &mut buffer[length..]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Payload<'a> {
    pub type_code: PayloadTypeCode,
    pub length: u32,
    pub content: PayloadTypeContent<'a>,
}

impl<'a> Payload<'a> {
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Payload<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let type_code = packet.payload_type();
        let length = packet.payload_length();
        let content_length = packet.payload_content_length();
        let (_, content) = PayloadTypeContent::parse(packet.payload(), type_code, content_length)?;

        Ok(Payload {
            type_code,
            length: length as u32,
            content,
        })
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        NetworkEndian::write_u16(&mut buffer[field::payload::TYPE], self.type_code as u16);
        NetworkEndian::write_u32(&mut buffer[field::payload::PAYLOAD_LENGTH], self.length);
        self.content.emit(
            &mut buffer[field::payload::PAYLOAD_LENGTH.end..],
            self.length as usize,
        );
        &mut buffer[(field::payload::PAYLOAD_LENGTH.end + self.length as usize)..]
    }
}

impl<'a> fmt::Display for Payload<'a> {
    /// Formats the Payload as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Payload: type_code={}, length={}, content={}",
            self.type_code, self.length, self.content,
        )
    }
}

/// A high-level representation of a DoIP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    pub protocol_version: u8,
    pub inverse_protocol_version: u8,
    pub payload: Payload<'a>,
}

impl<'a> Repr<'a> {
    /// Parses the packet/buffer and returns a high-level representation of the DoIP packet.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let payload = Payload::parse(packet)?;
        Ok(Repr {
            protocol_version: packet.protocol_version(),
            inverse_protocol_version: packet.inverse_protocol_version(),
            payload,
        })
    }

    /// Returns the length of the header.
    pub fn header_len(&self) -> usize {
        field::header::LENGTH
    }

    /// Returns the length of the buffer.
    pub fn buffer_len(&self) -> usize {
        self.header_len() + self.payload.length as usize
    }

    /// Emits the high-level representation of the DoIP packet into the provided packet/buffer.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_protocol_version(self.protocol_version);
        packet.set_inverse_protocol_version(self.inverse_protocol_version);
        packet.set_payload_type(self.payload.type_code);
        packet.set_payload_length(self.payload.length as usize);
        self.payload.emit(packet.payload());
    }
}

impl fmt::Display for PayloadTypeContent<'_> {
    /// Formats the payload as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PayloadTypeContent::GenericDoIPHeaderNegativeResponse => {
                write!(f, "Generic DoIP header negative response")
            }
            PayloadTypeContent::VehicleIdentificationRequest => {
                write!(f, "Vehicle identification request")
            }
            PayloadTypeContent::VehicleIdentificationRequestWithEID { eid } => {
                write!(f, "Vehicle identification request with EID: {:?}", eid)
            }
            PayloadTypeContent::VehicleIdentificationRequestWithVIN { vin } => {
                write!(f, "Vehicle identification request with VIN: {:?}", vin)
            }
            PayloadTypeContent::VehicleIdentificationResponseMessage {
                vin,
                logical_address,
                eid,
                gid,
                further_action,
                gid_sync_status,
            } => {
                write!(
                    f,
                    "Vehicle identification response message: VIN={:?}, logical_address={}, EID={:?}, GID={:?}, further_action={}, GID_sync_status={}",
                    vin, logical_address, eid, gid, further_action, gid_sync_status
                )
            }
            PayloadTypeContent::RoutingActivationRequest {
                source_address,
                activation_type,
                iso_reserved,
                oem_specific,
            } => {
                write!(
                    f,
                    "Routing activation request: source_address={}, activation_type={}, ISO_reserved={}, OEM_specific={}",
                    source_address, activation_type, iso_reserved, oem_specific
                )
            }
            PayloadTypeContent::RoutingActivationResponse {
                logical_address_tester,
                logical_address_doip_entity,
                routing_activation_response_code,
                iso_reserved,
                oem_specific,
            } => {
                write!(
                    f,
                    "Routing activation response: logical_address_tester={}, logical_address_doip_entity={}, routing_activation_response_code={}, ISO_reserved={}, OEM_specific={}",
                    logical_address_tester, logical_address_doip_entity, routing_activation_response_code, iso_reserved, oem_specific
                )
            }
            PayloadTypeContent::AliveCheckRequest => {
                write!(f, "Alive check request")
            }
            PayloadTypeContent::AliveCheckResponse { source_address } => {
                write!(f, "Alive check response: source_address={}", source_address)
            }
            PayloadTypeContent::DoIPEntityStatusRequest => {
                write!(f, "DoIP entity status request")
            }
            PayloadTypeContent::DoIPEntityStatusResponse {
                node_type,
                max_open_sockets,
                currently_open_sockets,
                max_data_size,
            } => {
                write!(
                    f,
                    "DoIP entity status response: node_type={}, max_open_sockets={}, currently_open_sockets={}, max_data_size={}",
                    node_type, max_open_sockets, currently_open_sockets, max_data_size
                )
            }
            PayloadTypeContent::DiagnosticPowerModeInformationRequest => {
                write!(f, "Diagnostic power mode information request")
            }
            PayloadTypeContent::DiagnosticPowerModeInformationResponse {
                diagnostic_power_mode,
            } => {
                write!(
                    f,
                    "Diagnostic power mode information response: diagnostic_power_mode={}",
                    diagnostic_power_mode
                )
            }
            PayloadTypeContent::DiagnosticMessage {
                source_address,
                target_address,
                user_data,
            } => {
                write!(
                    f,
                    "Diagnostic message: source_address={}, target_address={}, user_data={:?}",
                    source_address, target_address, user_data
                )
            }
            PayloadTypeContent::DiagnosticMessagePositiveAcknowledgement {
                source_address,
                target_address,
                ack_code,
                previous_diagnostic_message,
            } => {
                write!(
                    f,
                    "Diagnostic message positive acknowledgement: source_address={}, target_address={}, ack_code={}, previous_diagnostic_message={:?}",
                    source_address, target_address, ack_code, previous_diagnostic_message
                )
            }
            PayloadTypeContent::DiagnosticMessageNegativeAcknowledgement {
                source_address,
                target_address,
                nack_code,
                previous_diagnostic_message,
            } => {
                write!(
                    f,
                    "Diagnostic message negative acknowledgement: source_address={}, target_address={}, nack_code={}, previous_diagnostic_message={:?}",
                    source_address, target_address, nack_code, previous_diagnostic_message
                )
            }
        }
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

impl<'a> fmt::Display for Repr<'a> {
    /// Formats the high-level representation of the DoIP packet as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DoIP packet: protocol_version={}, inverse_protocol_version={}, payload={}",
            self.protocol_version, self.inverse_protocol_version, self.payload,
        )
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Repr<'a> {
    /// Formats the high-level representation of the DoIP packet for defmt.
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "DoIP packet: protocol_version={}, inverse_protocol_version={}, payload_type={}, payload_length={}, payload={}",
            self.protocol_version,
            self.inverse_protocol_version,
            self.payload.type_code,
            self.payload.length,
            self.payload.content,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deconstruct_without_payload() {
        static PACKET_BYTES_HEADER_ONLY: [u8; 8] = [0x01, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let packet = Packet::new_unchecked(&PACKET_BYTES_HEADER_ONLY[..]);
        assert_eq!(packet.protocol_version(), 0x01);
        assert_eq!(packet.inverse_protocol_version(), 0xFE);
        assert_eq!(
            packet.payload_type(),
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse
        );
        assert_eq!(packet.payload_length(), 0x00000000);
    }

    #[test]
    fn test_deconstruct_with_payload() {
        static PACKET_BYTES_WITH_PAYLOAD: [u8; 12] = [
            0x01, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x03, 0x02, 0x01,
        ];
        let packet = Packet::new_unchecked(&PACKET_BYTES_WITH_PAYLOAD[..]);
        assert_eq!(packet.protocol_version(), 0x01);
        assert_eq!(packet.inverse_protocol_version(), 0xFE);
        assert_eq!(
            packet.payload_type(),
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse
        );
        assert_eq!(packet.payload_length(), 0x00000004);
        assert_eq!(packet.payload(), [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_repr_parse() {
        let buffer = [0x02, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = Packet::new_checked(&buffer).unwrap();
        let repr = Repr::parse(&packet).unwrap();

        assert_eq!(repr.protocol_version, 0x02);
        assert_eq!(repr.inverse_protocol_version, 0xfd);
        assert_eq!(
            repr.payload.type_code,
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse
        );
        assert_eq!(repr.payload.length, 0);
        assert_eq!(
            repr.payload.content,
            PayloadTypeContent::GenericDoIPHeaderNegativeResponse
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::GenericDoIPHeaderNegativeResponse,
                length: 0,
                content: PayloadTypeContent::GenericDoIPHeaderNegativeResponse,
            },
        };

        let mut buffer = [0u8; 8]; // Adjust buffer size to match the header size
        let mut packet = Packet::new_unchecked(&mut buffer);
        repr.emit(&mut packet);

        assert_eq!(packet.protocol_version(), 0x02);
        assert_eq!(packet.inverse_protocol_version(), 0xfd);
        assert_eq!(
            packet.payload_type(),
            PayloadTypeCode::GenericDoIPHeaderNegativeResponse
        );
        assert_eq!(packet.payload_length(), 0);
    }

    fn round_trip_test(repr: Repr) {
        let mut buffer = [0u8; 1024]; // Adjust buffer size to match the header size and payload
        {
            let mut packet = Packet::new_unchecked(&mut buffer);
            repr.emit(&mut packet);
        }

        let packet = Packet::new_checked(&buffer).unwrap();
        let parsed_repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, parsed_repr);
    }

    #[test]
    fn test_repr_round_trip_generic_doip_header_negative_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::GenericDoIPHeaderNegativeResponse,
                length: field::payload::gdhna::LENGTH as u32,
                content: PayloadTypeContent::GenericDoIPHeaderNegativeResponse,
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_vehicle_identification_request() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleIdentificationRequest,
                length: field::payload::vir::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationRequest,
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_vehicle_identification_request_eid() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleIdentificationRequestEID,
                length: field::payload::vir_eid::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationRequestWithEID { eid: &[0; 6] },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_vehicle_identification_request_vin() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleIdentificationRequestVIN,
                length: field::payload::vir_vin::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationRequestWithVIN { vin: &[0; 17] },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_vehicle_announcement_message() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleAnnouncementMessage,
                length: field::payload::vam::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationResponseMessage {
                    vin: &[0; 17],
                    logical_address: 0,
                    eid: &[0; 6],
                    gid: &[0; 6],
                    further_action: 0,
                    gid_sync_status: 0,
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_routing_activation_request() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::RoutingActivationRequest,
                length: field::payload::ra_req::LENGTH as u32,
                content: PayloadTypeContent::RoutingActivationRequest {
                    source_address: 0,
                    activation_type: 0,
                    iso_reserved: 0,
                    oem_specific: 0,
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_routing_activation_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::RoutingActivationResponse,
                length: field::payload::ra_res::LENGTH as u32,
                content: PayloadTypeContent::RoutingActivationResponse {
                    logical_address_tester: 0,
                    logical_address_doip_entity: 0,
                    routing_activation_response_code: 0,
                    iso_reserved: 0,
                    oem_specific: 0,
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_alive_check_request() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::AliveCheckRequest,
                length: 0,
                content: PayloadTypeContent::AliveCheckRequest,
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_alive_check_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::AliveCheckResponse,
                length: 2,
                content: PayloadTypeContent::AliveCheckResponse { source_address: 0 },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_doip_entity_status_request() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DoIPEntityStatusRequest,
                length: 0,
                content: PayloadTypeContent::DoIPEntityStatusRequest,
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_doip_entity_status_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DoIPEntityStatusResponse,
                length: 7,
                content: PayloadTypeContent::DoIPEntityStatusResponse {
                    node_type: 0,
                    max_open_sockets: 0,
                    currently_open_sockets: 0,
                    max_data_size: 0,
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_diagnostic_power_mode_information_request() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DiagnosticPowerModeInformationRequest,
                length: 0,
                content: PayloadTypeContent::DiagnosticPowerModeInformationRequest,
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_diagnostic_power_mode_information_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DiagnosticPowerModeInformationResponse,
                length: 1,
                content: PayloadTypeContent::DiagnosticPowerModeInformationResponse {
                    diagnostic_power_mode: 0,
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_diagnostic_message() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DiagnosticMessage,
                length: field::payload::dm::DATA(3).end as u32,
                content: PayloadTypeContent::DiagnosticMessage {
                    source_address: 0,
                    target_address: 0,
                    user_data: &[0x22, 0xF1, 0x90],
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_diagnostic_message_ack() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DiagnosticMessageAck,
                length: field::payload::dm_xack::DATA(0).end as u32,
                content: PayloadTypeContent::DiagnosticMessagePositiveAcknowledgement {
                    source_address: 0,
                    target_address: 0,
                    ack_code: 0,
                    previous_diagnostic_message: &[],
                },
            },
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_diagnostic_message_nack() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::DiagnosticMessageNack,
                length: field::payload::dm_xack::DATA(0).end as u32,
                content: PayloadTypeContent::DiagnosticMessageNegativeAcknowledgement {
                    source_address: 0,
                    target_address: 0,
                    nack_code: 0,
                    previous_diagnostic_message: &[],
                },
            },
        };
        round_trip_test(repr);
    }
}
