use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

const MAX_REFERENCE_LENGTH: usize = 255;

/// Why an opaque payload reference was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOpaqueReference {
    reference_kind: &'static str,
    reason: &'static str,
}

impl InvalidOpaqueReference {
    const fn new(reference_kind: &'static str, reason: &'static str) -> Self {
        Self {
            reference_kind,
            reason,
        }
    }

    /// The public reference type that failed validation.
    #[must_use]
    pub const fn reference_kind(&self) -> &'static str {
        self.reference_kind
    }

    /// A non-sensitive explanation of the rejected shape.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for InvalidOpaqueReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {}: {}",
            self.reference_kind, self.reason
        )
    }
}

impl Error for InvalidOpaqueReference {}

fn validate_reference(
    value: &str,
    expected_prefix: &'static str,
    reference_kind: &'static str,
) -> Result<(), InvalidOpaqueReference> {
    if value.len() > MAX_REFERENCE_LENGTH {
        return Err(InvalidOpaqueReference::new(
            reference_kind,
            "reference exceeds 255 bytes",
        ));
    }

    let Some(identifier) = value.strip_prefix(expected_prefix) else {
        return Err(InvalidOpaqueReference::new(
            reference_kind,
            "reference has the wrong type prefix",
        ));
    };

    if identifier.is_empty() {
        return Err(InvalidOpaqueReference::new(
            reference_kind,
            "reference identifier is empty",
        ));
    }

    if !identifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(InvalidOpaqueReference::new(
            reference_kind,
            "reference must contain only ASCII letters, digits, underscore, or hyphen",
        ));
    }

    Ok(())
}

macro_rules! opaque_reference {
    ($name:ident, $prefix:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated opaque reference.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidOpaqueReference> {
                let value = value.into();
                validate_reference(&value, $prefix, stringify!($name))?;
                Ok(Self(value))
            }

            /// Returns the opaque identifier without revealing any storage location.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidOpaqueReference;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

opaque_reference!(
    BodyRef,
    "body_",
    "Opaque reference to a normalized HTTP request or response body."
);
opaque_reference!(
    BlobRef,
    "blob_",
    "Opaque reference to generic stream or raw payload material."
);
