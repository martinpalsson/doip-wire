use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;
use crate::{field, error::*, packet::*};

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