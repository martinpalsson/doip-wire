use core::fmt;
/// Enum representing the DoIP power mode.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DoIPPowerMode {
    /// DoIP power mode Not Ready
    NotReady = 0,
    /// DoIP power mode Ready
    Ready = 1,
    /// DoIP power mode Not Supported
    NotSupported = 2,
}

impl DoIPPowerMode {
    /// Parses a byte into a `DoIPPowerMode`.
    ///
    /// # Arguments
    ///
    /// * `value` - A byte representing the power mode.
    ///
    /// # Returns
    ///
    /// * `Some(DoIPPowerMode)` - The corresponding `DoIPPowerMode` if the value is valid.
    /// * `None` - If the value does not correspond to a valid `DoIPPowerMode`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DoIPPowerMode::NotReady),
            1 => Some(DoIPPowerMode::Ready),
            2 => Some(DoIPPowerMode::NotSupported),
            _ => None,
        }
    }

    /// Converts the `DoIPPowerMode` to a byte.
    ///
    /// # Returns
    ///
    /// * `u8` - A byte representing the `DoIPPowerMode`.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for DoIPPowerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DoIPPowerMode::NotReady => write!(f, "Not Ready"),
            DoIPPowerMode::Ready => write!(f, "Ready"),
            DoIPPowerMode::NotSupported => write!(f, "Not Supported"),
        }
    }
}
