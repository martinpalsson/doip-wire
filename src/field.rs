#![allow(non_snake_case)]

// Format of the DoIP header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Header syncronization pattern                      |
// |       Protocol version        |       Inverse protocol version      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              Payload                                |
// |  Payload type code  |  Payload length  |    Payload type content    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

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
