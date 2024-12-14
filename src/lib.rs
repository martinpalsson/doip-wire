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

mod field {
    #![allow(non_snake_case)]

    pub type Field = ::core::ops::Range<usize>;

    pub const PRC_VER: Field = 0..1;
    pub const IPC_VER: Field = 1..2;
    pub const PYL_TYP: Field = 2..4;
    pub const PYL_LEN: Field = 4..8;

    pub mod payload_type {

        pub mod vehicle_identification_response {
            use crate::field::Field;
            pub const VIN: Field = 0..17;
            pub const LA: Field = 17..19;
            pub const EID: Field = 19..25;
            pub const GID: Field = 25..31;
            pub const FTA: Field = 31..32;
            pub const GSS: Field = 32..33;
            pub const LENGTH: usize = 33;
        }
        pub mod vehicle_identification_request_eid {
            use crate::field::Field;
            pub const EID: Field = 0..6;
            pub const LENGTH: usize = 6;
        }

        pub mod vehicle_identification_request_vin {
            use crate::field::Field;
            pub const VIN: Field = 0..17;
            pub const LENGTH: usize = 17;
        }

        pub mod routing_activation_request {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const AT: Field = 2..3;
            pub const ISO_RES: Field = 3..7;
            pub const OEM_RES: Field = 7..11;
            pub const LENGTH: usize = 11;
        }

        pub mod routing_activation_response {
            use crate::field::Field;
            pub const LAT: Field = 0..2;
            pub const LADE: Field = 2..4;
            pub const RCODE: Field = 4..5;
            pub const ISO_RES: Field = 5..9;
            pub const OEM_RES: Field = 9..13;
            pub const LENGTH: usize = 13;
        }

        pub mod alive_check_response {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const LENGTH: usize = 2;
        }

        pub mod doip_entity_status_response {
            use crate::field::Field;
            pub const NT: Field = 0..1;
            pub const MOS: Field = 1..2;
            pub const COS: Field = 2..3;
            pub const MDS: Field = 3..7;
            pub const LENGTH: usize = 7;
        }

        pub mod diagnostic_power_mode_information_response {
            use crate::field::Field;
            pub const DPM: Field = 0..1;
            pub const LENGTH: usize = 1;
        }

        pub mod diagnostic_message {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const TA: Field = 2..4;
            pub const fn DATA(length: usize) -> Field {
                TA.end..(length)
            }
        }

        pub mod diag_message_xack {
            use crate::field::Field;
            pub const SA: Field = 0..2;
            pub const TA: Field = 2..4;
            pub const ACKC: Field = 4..5;
            pub const fn PYL_DMACK_DATA(length: usize) -> Field {
                ACKC.end..(length)
            }
        }
    }
}

/// The length of the DoIP header excluding payload.
pub const HEADER_LEN: usize = field::PYL_LEN.end;

/// Enum representing the different payload types in the DoIP protocol.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u16)]
pub enum PayloadType {
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

impl PayloadType {
    /// Converts a u16 to a PayloadType.
    ///
    /// # Arguments
    ///
    /// * `value` - A u16 value representing the payload type.
    ///
    /// # Returns
    ///
    /// * `Some(PayloadType)` - The corresponding PayloadType if the value is valid.
    /// * `None` - If the value does not correspond to a valid PayloadType.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(PayloadType::GenericDoIPHeaderNegativeResponse),
            0x0001 => Some(PayloadType::VehicleIdentificationRequest),
            0x0002 => Some(PayloadType::VehicleIdentificationRequestEID),
            0x0003 => Some(PayloadType::VehicleIdentificationRequestVIN),
            0x0004 => Some(PayloadType::VehicleAnnouncementMessage),
            0x0005 => Some(PayloadType::RoutingActivationRequest),
            0x0006 => Some(PayloadType::RoutingActivationResponse),
            0x0007 => Some(PayloadType::AliveCheckRequest),
            0x0008 => Some(PayloadType::AliveCheckResponse),
            0x4001 => Some(PayloadType::DoIPEntityStatusRequest),
            0x4002 => Some(PayloadType::DoIPEntityStatusResponse),
            0x4003 => Some(PayloadType::DiagnosticPowerModeInformationRequest),
            0x4004 => Some(PayloadType::DiagnosticPowerModeInformationResponse),
            0x8001 => Some(PayloadType::DiagnosticMessage),
            0x8002 => Some(PayloadType::DiagnosticMessageAck),
            0x8003 => Some(PayloadType::DiagnosticMessageNack),
            _ => None,
        }
    }
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PayloadType::GenericDoIPHeaderNegativeResponse => {
                write!(f, "Generic DoIP header negative response")
            }
            PayloadType::VehicleIdentificationRequest => {
                write!(f, "Vehicle identification request")
            }
            PayloadType::VehicleIdentificationRequestEID => {
                write!(f, "Vehicle identification request with EID")
            }
            PayloadType::VehicleIdentificationRequestVIN => {
                write!(f, "Vehicle identification request with VIN")
            }
            PayloadType::VehicleAnnouncementMessage => {
                write!(f, "Vehicle announcement message")
            }
            PayloadType::RoutingActivationRequest => {
                write!(f, "Routing activation request")
            }
            PayloadType::RoutingActivationResponse => {
                write!(f, "Routing activation response")
            }
            PayloadType::AliveCheckRequest => {
                write!(f, "Alive check request")
            }
            PayloadType::AliveCheckResponse => {
                write!(f, "Alive check response")
            }
            PayloadType::DoIPEntityStatusRequest => {
                write!(f, "DoIP entity status request")
            }
            PayloadType::DoIPEntityStatusResponse => {
                write!(f, "DoIP entity status response")
            }
            PayloadType::DiagnosticPowerModeInformationRequest => {
                write!(f, "Diagnostic power mode information request")
            }
            PayloadType::DiagnosticPowerModeInformationResponse => {
                write!(f, "Diagnostic power mode information response")
            }
            PayloadType::DiagnosticMessage => {
                write!(f, "Diagnostic message")
            }
            PayloadType::DiagnosticMessageAck => {
                write!(f, "Diagnostic message positive acknowledgement")
            }
            PayloadType::DiagnosticMessageNack => {
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

    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::PYL_LEN.end {
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
        data[field::PRC_VER.start]
    }

    pub fn inverse_protocol_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::IPC_VER.start]
    }

    pub fn payload_type(&self) -> PayloadType {
        let data = self.buffer.as_ref();
         match PayloadType::from_u16(NetworkEndian::read_u16(&data[field::PYL_TYP])) {
            Some(payload_type) => payload_type,
            None => PayloadType::GenericDoIPHeaderNegativeResponse,
         }
    }

    pub fn payload_length(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::PYL_LEN]) as usize
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::PRC_VER.start] = value;
    }

    pub fn set_inverse_protocol_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::IPC_VER.start] = value;
    }

    pub fn set_payload_type(&mut self, value: PayloadType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::PYL_TYP], value as u16);
    }

    pub fn set_payload_length(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::PYL_LEN], value as u32);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[HEADER_LEN..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    #[inline]
    pub fn payload(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[HEADER_LEN..]
    }
}

/// Represents the different types of payloads in the DoIP protocol.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Payload<'a> {
    GenericDoIPHeaderNegativeResponse,
    VehicleIdentificationRequest,
    VehicleIdentificationRequestWithEID {
        eid: &'a [u8; 6],
    },
    VehicleIdentificationRequestWithVIN {
        vin: &'a [u8; 17],
    },
    VehicleIdentificationResponseMessage {
        vin: &'a [u8; 17],
        logical_address: u16,
        eid: &'a [u8; 6],
        gid: &'a [u8; 6],
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

impl<'a> Payload<'a> {
    /// Parses the buffer and returns the corresponding payload.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A byte slice containing the data to be parsed.
    /// * `payload_type` - The type of payload to be parsed.
    ///
    /// # Returns
    ///
    /// * `Ok((remaining_buffer, payload))` - A tuple containing the remaining buffer and the parsed payload.
    /// * `Err(Error)` - An error if the buffer is too short or contains invalid data.
    pub fn parse(buffer: &'a [u8], payload_type: PayloadType) -> Result<(&'a [u8], Payload<'a>)> {
        let (length, payload);
        match payload_type {
            PayloadType::GenericDoIPHeaderNegativeResponse => {
                length = 0;
                payload = Payload::GenericDoIPHeaderNegativeResponse;
            }
            PayloadType::VehicleIdentificationRequest => {
                length = 0;
                payload = Payload::VehicleIdentificationRequest;
            }
            PayloadType::VehicleIdentificationRequestEID => {
                if buffer.len() < field::payload_type::vehicle_identification_request_eid::LENGTH {
                    return Err(Error);
                }
                let eid = buffer
                    .get(field::payload_type::vehicle_identification_request_eid::EID)
                    .ok_or(Error)?;
                length = field::payload_type::vehicle_identification_request_eid::LENGTH;
                payload = Payload::VehicleIdentificationRequestWithEID {
                    eid: eid.try_into().unwrap(),
                };
            }
            PayloadType::VehicleIdentificationRequestVIN => {
                if buffer.len() < field::payload_type::vehicle_identification_request_vin::LENGTH {
                    return Err(Error);
                }
                let vin = buffer
                    .get(field::payload_type::vehicle_identification_request_vin::VIN)
                    .ok_or(Error)?;
                length = field::payload_type::vehicle_identification_request_vin::LENGTH;
                payload = Payload::VehicleIdentificationRequestWithVIN {
                    vin: vin.try_into().unwrap(),
                };
            }
            PayloadType::VehicleAnnouncementMessage => {
                if buffer.len() < field::payload_type::vehicle_identification_response::LENGTH {
                    return Err(Error);
                }
                let vin = buffer
                    .get(field::payload_type::vehicle_identification_response::VIN)
                    .ok_or(Error)?;
                let logical_address = NetworkEndian::read_u16(
                    &buffer[field::payload_type::vehicle_identification_response::LA],
                );
                let eid = buffer
                    .get(field::payload_type::vehicle_identification_response::EID)
                    .ok_or(Error)?;
                let gid = buffer
                    .get(field::payload_type::vehicle_identification_response::GID)
                    .ok_or(Error)?;
                let further_action =
                    buffer[field::payload_type::vehicle_identification_response::FTA.start];
                let gid_sync_status =
                    buffer[field::payload_type::vehicle_identification_response::GSS.start];
                length = field::payload_type::vehicle_identification_response::LENGTH;
                payload = Payload::VehicleIdentificationResponseMessage {
                    vin: vin.try_into().unwrap(),
                    logical_address,
                    eid: eid.try_into().unwrap(),
                    gid: gid.try_into().unwrap(),
                    further_action,
                    gid_sync_status,
                };
            }
            PayloadType::DiagnosticMessage => {
                if buffer.len() < field::payload_type::diagnostic_message::DATA(0).end {
                    return Err(Error);
                }
                let source_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diagnostic_message::SA]);
                let target_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diagnostic_message::TA]);
                length = buffer.len();
                let user_data = &buffer[field::payload_type::diagnostic_message::DATA(length)];
                payload = Payload::DiagnosticMessage {
                    source_address,
                    target_address,
                    user_data,
                };
            }
            PayloadType::RoutingActivationRequest => {
                if buffer.len() < field::payload_type::routing_activation_request::LENGTH {
                    return Err(Error);
                }
                let source_address = NetworkEndian::read_u16(
                    &buffer[field::payload_type::routing_activation_request::SA],
                );
                let activation_type =
                    buffer[field::payload_type::routing_activation_request::AT.start];
                let iso_reserved = NetworkEndian::read_u32(
                    &buffer[field::payload_type::routing_activation_request::ISO_RES],
                );
                let oem_specific = NetworkEndian::read_u32(
                    &buffer[field::payload_type::routing_activation_request::OEM_RES],
                );
                length = field::payload_type::routing_activation_request::LENGTH;
                payload = Payload::RoutingActivationRequest {
                    source_address,
                    activation_type,
                    iso_reserved,
                    oem_specific,
                };
            }
            PayloadType::RoutingActivationResponse => {
                if buffer.len() < field::payload_type::routing_activation_response::LENGTH {
                    return Err(Error);
                }
                let logical_address_tester = NetworkEndian::read_u16(
                    &buffer[field::payload_type::routing_activation_response::LAT],
                );
                let logical_address_doip_entity = NetworkEndian::read_u16(
                    &buffer[field::payload_type::routing_activation_response::LADE],
                );
                let routing_activation_response_code =
                    buffer[field::payload_type::routing_activation_response::RCODE.start];
                let iso_reserved = NetworkEndian::read_u32(
                    &buffer[field::payload_type::routing_activation_response::ISO_RES],
                );
                let oem_specific = NetworkEndian::read_u32(
                    &buffer[field::payload_type::routing_activation_response::OEM_RES],
                );
                length = field::payload_type::routing_activation_response::LENGTH;
                payload = Payload::RoutingActivationResponse {
                    logical_address_tester,
                    logical_address_doip_entity,
                    routing_activation_response_code,
                    iso_reserved,
                    oem_specific,
                };
            }
            PayloadType::AliveCheckRequest => {
                length = 0;
                payload = Payload::AliveCheckRequest;
            }
            PayloadType::AliveCheckResponse => {
                if buffer.len() < field::payload_type::alive_check_response::LENGTH {
                    return Err(Error);
                }
                let source_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::alive_check_response::SA]);
                length = field::payload_type::alive_check_response::LENGTH;
                payload = Payload::AliveCheckResponse { source_address };
            }
            PayloadType::DoIPEntityStatusRequest => {
                length = 0;
                payload = Payload::DoIPEntityStatusRequest;
            }
            PayloadType::DoIPEntityStatusResponse => {
                if buffer.len() < field::payload_type::doip_entity_status_response::LENGTH {
                    return Err(Error);
                }
                let node_type = buffer[field::payload_type::doip_entity_status_response::NT.start];
                let max_open_sockets =
                    buffer[field::payload_type::doip_entity_status_response::MOS.start];
                let currently_open_sockets =
                    buffer[field::payload_type::doip_entity_status_response::COS.start];
                let max_data_size = NetworkEndian::read_u32(
                    &buffer[field::payload_type::doip_entity_status_response::MDS],
                );
                length = field::payload_type::doip_entity_status_response::LENGTH;
                payload = Payload::DoIPEntityStatusResponse {
                    node_type,
                    max_open_sockets,
                    currently_open_sockets,
                    max_data_size,
                };
            }
            PayloadType::DiagnosticPowerModeInformationRequest => {
                length = 0;
                payload = Payload::DiagnosticPowerModeInformationRequest;
            }
            PayloadType::DiagnosticPowerModeInformationResponse => {
                if buffer.len()
                    < field::payload_type::diagnostic_power_mode_information_response::LENGTH
                {
                    return Err(Error);
                }
                let diagnostic_power_mode = buffer
                    [field::payload_type::diagnostic_power_mode_information_response::DPM.start];
                length = field::payload_type::diagnostic_power_mode_information_response::LENGTH;
                payload = Payload::DiagnosticPowerModeInformationResponse {
                    diagnostic_power_mode,
                };
            }
            PayloadType::DiagnosticMessageAck => {
                if buffer.len() < field::payload_type::diag_message_xack::PYL_DMACK_DATA(0).end {
                    return Err(Error);
                }
                let source_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diag_message_xack::SA]);
                let target_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diag_message_xack::TA]);
                let ack_code = buffer[field::payload_type::diag_message_xack::ACKC.start];
                length = buffer.len();
                let previous_diagnostic_message =
                    &buffer[field::payload_type::diag_message_xack::PYL_DMACK_DATA(length)];
                payload = Payload::DiagnosticMessagePositiveAcknowledgement {
                    source_address,
                    target_address,
                    ack_code,
                    previous_diagnostic_message,
                };
            }
            PayloadType::DiagnosticMessageNack => {
                if buffer.len() < field::payload_type::diag_message_xack::PYL_DMACK_DATA(0).end {
                    return Err(Error);
                }
                let source_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diag_message_xack::SA]);
                let target_address =
                    NetworkEndian::read_u16(&buffer[field::payload_type::diag_message_xack::TA]);
                let nack_code = buffer[field::payload_type::diag_message_xack::ACKC.start];
                length = buffer.len();
                let previous_diagnostic_message =
                    &buffer[field::payload_type::diag_message_xack::PYL_DMACK_DATA(length)];
                payload = Payload::DiagnosticMessageNegativeAcknowledgement {
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
    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match *self {
            Payload::GenericDoIPHeaderNegativeResponse => {
                length = 0;
            }
            Payload::VehicleIdentificationRequest => {
                length = 0;
            }
            Payload::VehicleIdentificationRequestWithEID { eid } => {
                buffer[0..6].copy_from_slice(eid);
                length = 6;
            }
            Payload::VehicleIdentificationRequestWithVIN { vin } => {
                buffer[0..17].copy_from_slice(vin);
                length = 17;
            }
            Payload::VehicleIdentificationResponseMessage {
                vin,
                logical_address,
                eid,
                gid,
                further_action,
                gid_sync_status,
            } => {
                buffer[0..17].copy_from_slice(vin);
                NetworkEndian::write_u16(&mut buffer[17..19], logical_address);
                buffer[19..25].copy_from_slice(eid);
                buffer[25..31].copy_from_slice(gid);
                buffer[31] = further_action;
                buffer[32] = gid_sync_status;
                length = 33;
            }
            Payload::DiagnosticMessage {
                source_address,
                target_address,
                user_data,
            } => {
                NetworkEndian::write_u16(&mut buffer[0..2], source_address);
                NetworkEndian::write_u16(&mut buffer[2..4], target_address);
                buffer[4..4 + user_data.len()].copy_from_slice(user_data);
                length = 4 + user_data.len();
            }
            Payload::RoutingActivationRequest {
                source_address,
                activation_type,
                iso_reserved,
                oem_specific,
            } => {
                NetworkEndian::write_u16(&mut buffer[0..2], source_address);
                buffer[2] = activation_type;
                NetworkEndian::write_u32(&mut buffer[3..7], iso_reserved);
                NetworkEndian::write_u32(&mut buffer[7..11], oem_specific);
                length = 11;
            }
            Payload::RoutingActivationResponse {
                logical_address_tester,
                logical_address_doip_entity,
                routing_activation_response_code,
                iso_reserved,
                oem_specific,
            } => {
                NetworkEndian::write_u16(&mut buffer[0..2], logical_address_tester);
                NetworkEndian::write_u16(&mut buffer[2..4], logical_address_doip_entity);
                buffer[4] = routing_activation_response_code;
                NetworkEndian::write_u32(&mut buffer[5..9], iso_reserved);
                NetworkEndian::write_u32(&mut buffer[9..13], oem_specific);
                length = 13;
            }
            Payload::AliveCheckRequest => {
                length = 0;
            }
            Payload::AliveCheckResponse { source_address } => {
                NetworkEndian::write_u16(&mut buffer[0..2], source_address);
                length = 2;
            }
            Payload::DoIPEntityStatusRequest => {
                length = 0;
            }
            Payload::DoIPEntityStatusResponse {
                node_type,
                max_open_sockets,
                currently_open_sockets,
                max_data_size,
            } => {
                buffer[0] = node_type;
                buffer[1] = max_open_sockets;
                buffer[2] = currently_open_sockets;
                NetworkEndian::write_u32(&mut buffer[3..7], max_data_size);
                length = 7;
            }
            Payload::DiagnosticPowerModeInformationRequest => {
                length = 0;
            }
            Payload::DiagnosticPowerModeInformationResponse {
                diagnostic_power_mode,
            } => {
                buffer[0] = diagnostic_power_mode;
                length = 1;
            }
            Payload::DiagnosticMessagePositiveAcknowledgement {
                source_address,
                target_address,
                ack_code,
                previous_diagnostic_message,
            } => {
                NetworkEndian::write_u16(&mut buffer[0..2], source_address);
                NetworkEndian::write_u16(&mut buffer[2..4], target_address);
                buffer[4] = ack_code;
                buffer[5..5 + previous_diagnostic_message.len()]
                    .copy_from_slice(previous_diagnostic_message);
                length = 5 + previous_diagnostic_message.len();
            }
            Payload::DiagnosticMessageNegativeAcknowledgement {
                source_address,
                target_address,
                nack_code,
                previous_diagnostic_message,
            } => {
                NetworkEndian::write_u16(&mut buffer[0..2], source_address);
                NetworkEndian::write_u16(&mut buffer[2..4], target_address);
                buffer[4] = nack_code;
                buffer[5..5 + previous_diagnostic_message.len()]
                    .copy_from_slice(previous_diagnostic_message);
                length = 5 + previous_diagnostic_message.len();
            }
        }
        &mut buffer[length..]
    }
}

/// A high-level representation of a DoIP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    pub protocol_version: u8,
    pub inverse_protocol_version: u8,
    pub payload_type: PayloadType,
    pub payload_length: u32,
    pub payload: Payload<'a>,
}

impl<'a> Repr<'a> {
    /// Parses the packet/buffer and returns a high-level representation of the DoIP packet.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let payload_type = packet.payload_type();
        let payload_length = packet.payload_length();
        let (remaining, payload) = Payload::parse(packet.payload(), payload_type)?;
        if !remaining.is_empty() {
            return Err(Error);
        }
        Ok(Repr {
            protocol_version: packet.protocol_version(),
            inverse_protocol_version: packet.inverse_protocol_version(),
            payload_type,
            payload_length: payload_length as u32,
            payload,
        })
    }

    /// Returns the length of the header.
    pub fn header_len(&self) -> usize {
        HEADER_LEN
    }

    /// Returns the length of the buffer.
    pub fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_length as usize
    }

    /// Emits the high-level representation of the DoIP packet into the provided packet/buffer.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_protocol_version(self.protocol_version);
        packet.set_inverse_protocol_version(self.inverse_protocol_version);
        packet.set_payload_type(self.payload_type);
        packet.set_payload_length(self.payload_length as usize);
        let remaining = packet.payload();
        self.payload.emit(remaining);
    }
}

impl fmt::Display for Payload<'_> {
    /// Formats the payload as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Payload::GenericDoIPHeaderNegativeResponse => {
                write!(f, "Generic DoIP header negative response")
            }
            Payload::VehicleIdentificationRequest => {
                write!(f, "Vehicle identification request")
            }
            Payload::VehicleIdentificationRequestWithEID { eid } => {
                write!(f, "Vehicle identification request with EID: {:?}", eid)
            }
            Payload::VehicleIdentificationRequestWithVIN { vin } => {
                write!(f, "Vehicle identification request with VIN: {:?}", vin)
            }
            Payload::VehicleIdentificationResponseMessage {
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
            Payload::RoutingActivationRequest {
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
            Payload::RoutingActivationResponse {
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
            Payload::AliveCheckRequest => {
                write!(f, "Alive check request")
            }
            Payload::AliveCheckResponse { source_address } => {
                write!(f, "Alive check response: source_address={}", source_address)
            }
            Payload::DoIPEntityStatusRequest => {
                write!(f, "DoIP entity status request")
            }
            Payload::DoIPEntityStatusResponse {
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
            Payload::DiagnosticPowerModeInformationRequest => {
                write!(f, "Diagnostic power mode information request")
            }
            Payload::DiagnosticPowerModeInformationResponse {
                diagnostic_power_mode,
            } => {
                write!(
                    f,
                    "Diagnostic power mode information response: diagnostic_power_mode={}",
                    diagnostic_power_mode
                )
            }
            Payload::DiagnosticMessage {
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
            Payload::DiagnosticMessagePositiveAcknowledgement {
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
            Payload::DiagnosticMessageNegativeAcknowledgement {
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
            "DoIP packet: protocol_version={}, inverse_protocol_version={}, payload_type={}, payload_length={}, payload={}",
            self.protocol_version,
            self.inverse_protocol_version,
            self.payload_type,
            self.payload_length,
            self.payload,
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
            self.payload_type,
            self.payload_length,
            self.payload,
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
        assert_eq!(packet.payload_type(), PayloadType::GenericDoIPHeaderNegativeResponse);
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
        assert_eq!(packet.payload_type(), PayloadType::GenericDoIPHeaderNegativeResponse);
        assert_eq!(packet.payload_length(), 0x00000004);
        assert_eq!(packet.payload(), [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_parse_and_emit_generic_doip_header_negative_response() {
        let buffer = [];
        let payload_type = PayloadType::GenericDoIPHeaderNegativeResponse;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        assert!(matches!(
            payload,
            Payload::GenericDoIPHeaderNegativeResponse
        ));

        let mut emit_buffer = [0u8; 0];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
    }

    #[test]
    fn test_parse_and_emit_vehicle_identification_request() {
        let buffer = [];
        let payload_type = PayloadType::VehicleIdentificationRequest;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        assert!(matches!(payload, Payload::VehicleIdentificationRequest));

        let mut emit_buffer = [0u8; 0];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
    }

    #[test]
    fn test_parse_and_emit_vehicle_identification_request_with_eid() {
        let buffer = [1, 2, 3, 4, 5, 6];
        let payload_type = PayloadType::VehicleIdentificationRequestEID;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::VehicleIdentificationRequestWithEID { eid } = payload {
            assert_eq!(eid, &[1, 2, 3, 4, 5, 6]);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 6];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_parse_and_emit_vehicle_identification_request_with_vin() {
        let buffer = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        let payload_type = PayloadType::VehicleIdentificationRequestVIN;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::VehicleIdentificationRequestWithVIN { vin } = payload {
            assert_eq!(
                vin,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
            );
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 17];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(
            emit_buffer,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        );
    }

    #[test]
    fn test_parse_and_emit_vehicle_identification_response_message() {
        let buffer = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, // VIN
            0x12, 0x34, // Logical address
            18, 19, 20, 21, 22, 23, // EID
            24, 25, 26, 27, 28, 29, // GID
            30, // Further action
            31, // GID sync status
        ];
        let payload_type = PayloadType::VehicleAnnouncementMessage;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::VehicleIdentificationResponseMessage {
            vin,
            logical_address,
            eid,
            gid,
            further_action,
            gid_sync_status,
        } = payload
        {
            assert_eq!(
                vin,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
            );
            assert_eq!(logical_address, 0x1234);
            assert_eq!(eid, &[18, 19, 20, 21, 22, 23]);
            assert_eq!(gid, &[24, 25, 26, 27, 28, 29]);
            assert_eq!(further_action, 30);
            assert_eq!(gid_sync_status, 31);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 33];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_diagnostic_message() {
        let buffer = [
            0x12, 0x34, // Source address
            0x56, 0x78, // Target address
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // User data
        ];
        let payload_type = PayloadType::DiagnosticMessage;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::DiagnosticMessage {
            source_address,
            target_address,
            user_data,
        } = payload
        {
            assert_eq!(source_address, 0x1234);
            assert_eq!(target_address, 0x5678);
            assert_eq!(user_data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 14];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_routing_activation_request() {
        let buffer = [
            0x12, 0x34, // Source address
            0x56, // Activation type
            0x00, 0x00, 0x00, 0x01, // ISO reserved
            0x00, 0x00, 0x00, 0x02, // OEM specific
        ];
        let payload_type = PayloadType::RoutingActivationRequest;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::RoutingActivationRequest {
            source_address,
            activation_type,
            iso_reserved,
            oem_specific,
        } = payload
        {
            assert_eq!(source_address, 0x1234);
            assert_eq!(activation_type, 0x56);
            assert_eq!(iso_reserved, 1);
            assert_eq!(oem_specific, 2);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 11];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_routing_activation_response() {
        let buffer = [
            0x12, 0x34, // Logical address tester
            0x56, 0x78, // Logical address DoIP entity
            0x9A, // Routing activation response code
            0x00, 0x00, 0x00, 0x01, // ISO reserved
            0x00, 0x00, 0x00, 0x02, // OEM specific
        ];
        let payload_type = PayloadType::RoutingActivationResponse;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::RoutingActivationResponse {
            logical_address_tester,
            logical_address_doip_entity,
            routing_activation_response_code,
            iso_reserved,
            oem_specific,
        } = payload
        {
            assert_eq!(logical_address_tester, 0x1234);
            assert_eq!(logical_address_doip_entity, 0x5678);
            assert_eq!(routing_activation_response_code, 0x9A);
            assert_eq!(iso_reserved, 1);
            assert_eq!(oem_specific, 2);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 13];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_alive_check_request() {
        let buffer = [];
        let payload_type = PayloadType::AliveCheckRequest;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        assert!(matches!(payload, Payload::AliveCheckRequest));

        let mut emit_buffer = [0u8; 0];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
    }

    #[test]
    fn test_parse_and_emit_alive_check_response() {
        let buffer = [
            0x12, 0x34, // Source address
        ];
        let payload_type = PayloadType::AliveCheckResponse;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::AliveCheckResponse { source_address } = payload {
            assert_eq!(source_address, 0x1234);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 2];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_doip_entity_status_request() {
        let buffer = [];
        let payload_type = PayloadType::DoIPEntityStatusRequest;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        assert!(matches!(payload, Payload::DoIPEntityStatusRequest));

        let mut emit_buffer = [0u8; 0];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
    }

    #[test]
    fn test_parse_and_emit_doip_entity_status_response() {
        let buffer = [
            0x01, // Node type
            0x02, // Max open sockets
            0x03, // Currently open sockets
            0x00, 0x00, 0x00, 0x04, // Max data size
        ];
        let payload_type = PayloadType::DoIPEntityStatusResponse;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::DoIPEntityStatusResponse {
            node_type,
            max_open_sockets,
            currently_open_sockets,
            max_data_size,
        } = payload
        {
            assert_eq!(node_type, 0x01);
            assert_eq!(max_open_sockets, 0x02);
            assert_eq!(currently_open_sockets, 0x03);
            assert_eq!(max_data_size, 0x04);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 7];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_diagnostic_power_mode_information_request() {
        let buffer = [];
        let payload_type = PayloadType::DiagnosticPowerModeInformationRequest;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        assert!(matches!(
            payload,
            Payload::DiagnosticPowerModeInformationRequest
        ));

        let mut emit_buffer = [0u8; 0];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
    }

    #[test]
    fn test_parse_and_emit_diagnostic_power_mode_information_response() {
        let buffer = [
            0x01, // Diagnostic power mode
        ];
        let payload_type = PayloadType::DiagnosticPowerModeInformationResponse;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::DiagnosticPowerModeInformationResponse {
            diagnostic_power_mode,
        } = payload
        {
            assert_eq!(diagnostic_power_mode, 0x01);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 1];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_diagnostic_message_positive_acknowledgement() {
        let buffer = [
            0x12, 0x34, // Source address
            0x56, 0x78, // Target address
            0x9A, // Ack code
            1, 2, 3, 4, 5, // Previous diagnostic message
        ];
        let payload_type = PayloadType::DiagnosticMessageAck;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::DiagnosticMessagePositiveAcknowledgement {
            source_address,
            target_address,
            ack_code,
            previous_diagnostic_message,
        } = payload
        {
            assert_eq!(source_address, 0x1234);
            assert_eq!(target_address, 0x5678);
            assert_eq!(ack_code, 0x9A);
            assert_eq!(previous_diagnostic_message, &[1, 2, 3, 4, 5]);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 10];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }

    #[test]
    fn test_parse_and_emit_diagnostic_message_negative_acknowledgement() {
        let buffer = [
            0x12, 0x34, // Source address
            0x56, 0x78, // Target address
            0x9A, // Nack code
            1, 2, 3, 4, 5, // Previous diagnostic message
        ];
        let payload_type = PayloadType::DiagnosticMessageNack;
        let (remaining, payload) = Payload::parse(&buffer, payload_type).unwrap();
        assert_eq!(remaining, &[]);
        if let Payload::DiagnosticMessageNegativeAcknowledgement {
            source_address,
            target_address,
            nack_code,
            previous_diagnostic_message,
        } = payload
        {
            assert_eq!(source_address, 0x1234);
            assert_eq!(target_address, 0x5678);
            assert_eq!(nack_code, 0x9A);
            assert_eq!(previous_diagnostic_message, &[1, 2, 3, 4, 5]);
        } else {
            panic!("Unexpected payload type");
        }

        let mut emit_buffer = [0u8; 10];
        let remaining = payload.emit(&mut emit_buffer);
        assert_eq!(remaining, &[]);
        assert_eq!(emit_buffer, buffer);
    }
}