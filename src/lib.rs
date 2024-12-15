//! # DoIP-wire
//!
//! This crate provides the means for parsing byte arrays into higher-level
//! DoIP representations, and vice versa. It is designed to be used in embedded
//! environments and is a no-std crate.
//!
//! ## Examples
//! ### Parsing
//!
//! ```rust
//! use doip_wire::packet::Packet;
//! use doip_wire::payload::{Payload, PayloadTypeCode, PayloadTypeContent, Repr};
//!
//! let buffer = [0x02, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//! let packet = Packet::new_checked(&buffer).unwrap();
//! let repr = Repr::parse(&packet).unwrap();
//!
//! assert_eq!(repr.protocol_version, 0x02);
//! assert_eq!(repr.inverse_protocol_version, 0xfd);
//! assert_eq!(repr.payload.type_code, PayloadTypeCode::GenericDoIPHeaderNegativeResponse);
//! assert_eq!(repr.payload.length, 0);
//! assert_eq!(repr.payload.content, PayloadTypeContent::GenericDoIPHeaderNegativeResponse);
//! ```
//!
//! ### Emitting
//!
//! ```rust
//! use doip_wire::packet::Packet;
//! use doip_wire::payload::{Payload, PayloadTypeCode, PayloadTypeContent, Repr};
//!
//! let repr = Repr {
//!     protocol_version: 0x02,
//!     inverse_protocol_version: 0xfd,
//!     payload: Payload {
//!     type_code: PayloadTypeCode::DiagnosticMessage,
//!     length: 7,
//!     content: PayloadTypeContent::DiagnosticMessage {
//!         source_address: 0x0e80,
//!         target_address: 0x0101,
//!         user_data: &[0x22, 0xF1, 0x90],
//!         },
//!     },
//! };
//!
//! let mut buffer = [0u8; 1024]; // Static buffer size
//! let mut packet = Packet::new_unchecked(&mut buffer);
//! repr.emit(&mut packet);
//!
//! assert_eq!(packet.protocol_version(), 0x02);
//! assert_eq!(packet.inverse_protocol_version(), 0xfd);
//! assert_eq!(packet.payload_type(), PayloadTypeCode::DiagnosticMessage);
//! assert_eq!(packet.payload_length(), 7);
//! assert_eq!(packet.payload_content(), [0x0e, 0x80, 0x01, 0x01, 0x22, 0xF1, 0x90]);
//! assert_eq!(packet.message(), [0x02, 0xfd, 0x80, 0x01, 0x00, 0x00, 0x00, 0x07, 0x0e, 0x80, 0x01, 0x01, 0x22, 0xF1, 0x90]);
//! ```
//!
//! ## Modules
//! The `doip-wire` crate provides the following modules:
//!
//! - `error`: Contains the error type for DoIP packets.
//! - `field`: Contains the field definitions for the DoIP header and payload.
//! - `packet`: Contains the `Packet` type for parsing DoIP packets.
//! - `payload`: Contains the `Payload` type for parsing DoIP payloads.
//!
//! ## Notes
//! The `doip-wire` crate is a no-std crate, and it can be used in embedded environments.
//!
//! The `doip-wire` crate is based on the `smoltcp` crate, and it is a stripped-down version of the `smoltcp` crate.
//!
//! The `doip-wire` crate is a work in progress, and it is not yet feature-complete.
//!

pub mod error;
pub mod field;
pub mod packet;
pub mod payload;
pub mod types;

#[cfg(test)]
mod test {
    use crate::{
        field,
        packet::Packet,
        payload::{Payload, PayloadTypeCode, PayloadTypeContent, Repr},
        types::DoIPPowerMode,
    };

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
        assert_eq!(packet.payload_content(), [0x04, 0x03, 0x02, 0x01]);
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

    fn round_trip_test_with_bytes(repr: Repr, expected_bytes: &[u8]) {
        let mut buffer = vec![0u8; expected_bytes.len()];
        {
            let mut packet = Packet::new_unchecked(&mut buffer);
            repr.emit(&mut packet);
        }

        assert_eq!(&buffer, expected_bytes);

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
        round_trip_test_with_bytes(repr, &[0x02, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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
        round_trip_test_with_bytes(repr, &[0x02, 0xfd, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_repr_round_trip_vehicle_identification_request_eid() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleIdentificationRequestEID,
                length: field::payload::vir_eid::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationRequestWithEID {
                    eid: &[0, 1, 2, 3, 4, 5],
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            ],
        );
    }

    #[test]
    fn test_repr_round_trip_vehicle_identification_request_vin() {
        let vin_bytes = [
            89, 83, 51, 68, 68, 55, 56, 78, 52, 88, 55, 48, 53, 53, 51, 50, 48,
        ];
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleIdentificationRequestVIN,
                length: field::payload::vir_vin::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationRequestWithVIN {
                    vin: &vin_bytes,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x00, 0x03, 0x00, 0x00, 0x00, 0x11, 89, 83, 51, 68, 68, 55, 56, 78, 52,
                88, 55, 48, 53, 53, 51, 50, 48,
            ],
        );
    }

    #[test]
    fn test_repr_round_trip_vehicle_announcement_message() {
        let vin_bytes = [
            83, 66, 77, 49, 50, 65, 66, 65, 51, 80, 87, 48, 48, 48, 48, 48, 49,
        ];
        let eid_bytes = [1, 2, 3, 4, 5, 6];
        let gid_bytes = [6, 5, 4, 3, 2, 1];
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::VehicleAnnouncementMessage,
                length: field::payload::vam::LENGTH as u32,
                content: PayloadTypeContent::VehicleIdentificationResponseMessage {
                    vin: &vin_bytes,
                    logical_address: 0,
                    eid: &eid_bytes,
                    gid: &gid_bytes,
                    further_action: 0,
                    gid_sync_status: 0,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x00, 0x21, 83, 66, 77, 49, 50, 65, 66, 65, 51,
                80, 87, 48, 48, 48, 48, 48, 49, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00,
            ],
        );
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
                    source_address: 0x0101,
                    activation_type: 0,
                    iso_reserved: 0xA0A0A0A0,
                    oem_specific: 0xC0C0C0C0,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0B, 0x01, 0x01, 0x00, 0xA0, 0xA0, 0xA0,
                0xA0, 0xC0, 0xC0, 0xC0, 0xC0,
            ],
        );
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
                    logical_address_tester: 0x0e80,
                    logical_address_doip_entity: 0x0101,
                    routing_activation_response_code: 0,
                    iso_reserved: 0xBEEFBABE,
                    oem_specific: 0xDEADBEA7,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0D, 0x0E, 0x80, 0x01, 0x01, 0x00, 0xBE,
                0xEF, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xA7,
            ],
        );
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
        round_trip_test_with_bytes(repr, &[0x02, 0xfd, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_repr_round_trip_alive_check_response() {
        let repr = Repr {
            protocol_version: 0x02,
            inverse_protocol_version: 0xfd,
            payload: Payload {
                type_code: PayloadTypeCode::AliveCheckResponse,
                length: 2,
                content: PayloadTypeContent::AliveCheckResponse {
                    source_address: 0x0101,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[0x02, 0xfd, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01],
        );
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
        round_trip_test_with_bytes(repr, &[0x02, 0xfd, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00]);
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
                    max_open_sockets: 2,
                    currently_open_sockets: 0,
                    max_data_size: 1024,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x40, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04,
                0x00,
            ],
        );
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
        round_trip_test_with_bytes(repr, &[0x02, 0xfd, 0x40, 0x03, 0x00, 0x00, 0x00, 0x00]);
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
                    diagnostic_power_mode: DoIPPowerMode::Ready,
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[0x02, 0xfd, 0x40, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01],
        );
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
                    source_address: 0x0e80,
                    target_address: 0x0101,
                    user_data: &[0x22, 0xF1, 0x90],
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x80, 0x01, 0x00, 0x00, 0x00, 0x07, 0x0E, 0x80, 0x01, 0x01, 0x22, 0xF1,
                0x90,
            ],
        );
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
                    source_address: 0x0101,
                    target_address: 0x0e80,
                    ack_code: 0,
                    previous_diagnostic_message: &[],
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x80, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x0E, 0x80, 0x00,
            ],
        );
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
                    source_address: 0x0101,
                    target_address: 0x0e80,
                    nack_code: 0,
                    previous_diagnostic_message: &[],
                },
            },
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x02, 0xfd, 0x80, 0x03, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x0E, 0x80, 0x00,
            ],
        );
    }
}
