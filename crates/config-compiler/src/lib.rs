//! Deterministic, protected compilation of layered sing-box JSON configuration.
//!
//! A [`CompiledConfig`] is returned only after compiler invariants and the supplied
//! [`RuntimeConfigValidator`] have both accepted the final JSON. Runtime adapters
//! should accept this type at their commit boundary instead of accepting arbitrary
//! JSON strings.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

/// Namespace reserved for object definitions owned by FlowProbe.
pub const RESERVED_PREFIX: &str = "__flowprobe_";

/// Stable marker used in all user-inspectable representations of secret values.
pub const REDACTED: &str = "[REDACTED]";

/// Configuration layer associated with a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfigLayer {
    SystemBase,
    UserProfile,
    RuntimeOverlay,
    Compiled,
}

/// Severity of a compiler diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverity {
    Info,
    Error,
}

/// Stable, machine-readable diagnostic categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCode {
    InvalidJson,
    RootMustBeObject,
    DuplicateObjectKey,
    ReservedNamespace,
    ProtectedObjectReplacement,
    IdentityConflict,
    DuplicateTag,
    InvalidStructure,
    RuntimeValidationRejected,
    RuntimeValidatorUnavailable,
    ConfigValidated,
}

/// A safe diagnostic that never contains raw configuration values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    code: DiagnosticCode,
    severity: DiagnosticSeverity,
    layer: ConfigLayer,
    path: String,
    message: String,
}

impl Diagnostic {
    #[must_use]
    pub fn code(&self) -> DiagnosticCode {
        self.code
    }

    #[must_use]
    pub fn severity(&self) -> DiagnosticSeverity {
        self.severity
    }

    #[must_use]
    pub fn layer(&self) -> ConfigLayer {
        self.layer
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    fn error(
        code: DiagnosticCode,
        layer: ConfigLayer,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Error,
            layer,
            path: path.into(),
            message: message.into(),
        }
    }

    fn validated() -> Self {
        Self {
            code: DiagnosticCode::ConfigValidated,
            severity: DiagnosticSeverity::Info,
            layer: ConfigLayer::Compiled,
            path: "$".to_owned(),
            message: "compiled configuration passed compiler and runtime validation".to_owned(),
        }
    }
}

/// Structured diagnostics produced by parsing or compilation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReport {
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticReport {
    /// All diagnostics in deterministic discovery order.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Whether the report contains at least one error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

/// Parsing or compilation failure. Inspect [`Self::report`] for safe details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    report: DiagnosticReport,
}

impl ConfigError {
    fn from_diagnostic(diagnostic: Diagnostic) -> Self {
        Self {
            report: DiagnosticReport {
                diagnostics: vec![diagnostic],
            },
        }
    }

    fn from_report(report: DiagnosticReport) -> Self {
        Self { report }
    }

    /// Structured, redaction-safe failure details.
    #[must_use]
    pub fn report(&self) -> &DiagnosticReport {
        &self.report
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "configuration compilation failed with {} diagnostic(s)",
            self.report.diagnostics.len()
        )
    }
}

impl Error for ConfigError {}

macro_rules! config_layer {
    ($name:ident, $layer:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone)]
        pub struct $name(Value);

        impl $name {
            /// Parse a strict JSON object. Duplicate object keys are rejected.
            pub fn parse(source: &str) -> Result<Self, ConfigError> {
                parse_layer(source, $layer).map(Self)
            }

            /// Build a layer from an already parsed JSON value.
            pub fn from_value(value: Value) -> Result<Self, ConfigError> {
                ensure_object(value, $layer).map(Self)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&RedactedValue(&self.0))
                    .finish()
            }
        }
    };
}

config_layer!(
    SystemBase,
    ConfigLayer::SystemBase,
    "FlowProbe-owned base configuration, including protected internal objects."
);
config_layer!(
    UserProfile,
    ConfigLayer::UserProfile,
    "User-owned ordinary sing-box configuration. Reserved names are rejected."
);
config_layer!(
    RuntimeOverlay,
    ConfigLayer::RuntimeOverlay,
    "Trusted ephemeral runtime values such as ports, interfaces, and exclusions."
);

/// Failure returned by an independent runtime/schema validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeValidationFailure {
    /// The runtime rejected the canonical configuration.
    Rejected,
    /// The validator could not run, so no validated artifact may be produced.
    Unavailable,
}

/// Boundary implemented by the managed runtime adapter.
///
/// The input contains operational secrets and must not be logged. Returning an error
/// deliberately carries no raw validator output because upstream errors may echo
/// credentials. Runtime adapters should log their own separately redacted details.
pub trait RuntimeConfigValidator: Send + Sync {
    fn validate(&self, canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure>;
}

/// Compiler bound to the runtime validator required for the final validation step.
pub struct ConfigCompiler<V> {
    validator: V,
}

impl<V> ConfigCompiler<V>
where
    V: RuntimeConfigValidator,
{
    #[must_use]
    pub fn new(validator: V) -> Self {
        Self { validator }
    }

    /// Compile all three layers into one canonical, validated configuration.
    pub fn compile(
        &self,
        system_base: &SystemBase,
        user_profile: &UserProfile,
        runtime_overlay: &RuntimeOverlay,
    ) -> Result<CompiledConfig, ConfigError> {
        let mut report = DiagnosticReport::default();

        validate_layer(&system_base.0, ConfigLayer::SystemBase, &mut report);
        validate_layer(&user_profile.0, ConfigLayer::UserProfile, &mut report);
        validate_layer(&runtime_overlay.0, ConfigLayer::RuntimeOverlay, &mut report);
        reject_reserved_user_definitions(&user_profile.0, "$", &mut report);

        if report.has_errors() {
            return Err(ConfigError::from_report(report));
        }

        let mut compiled = system_base.0.clone();
        merge_value(
            &mut compiled,
            &user_profile.0,
            MergePolicy::UserProfile,
            "$",
            false,
            false,
            &mut report,
        );
        merge_value(
            &mut compiled,
            &runtime_overlay.0,
            MergePolicy::RuntimeOverlay,
            "$",
            false,
            false,
            &mut report,
        );
        validate_layer(&compiled, ConfigLayer::Compiled, &mut report);

        if report.has_errors() {
            return Err(ConfigError::from_report(report));
        }

        sort_keys_recursive(&mut compiled);

        let runtime_json = serde_json::to_string(&compiled).map_err(|_| {
            ConfigError::from_diagnostic(Diagnostic::error(
                DiagnosticCode::InvalidStructure,
                ConfigLayer::Compiled,
                "$",
                "compiled configuration could not be serialized",
            ))
        })?;

        if let Err(failure) = self.validator.validate(&runtime_json) {
            let (code, message) = match failure {
                RuntimeValidationFailure::Rejected => (
                    DiagnosticCode::RuntimeValidationRejected,
                    "runtime validator rejected the compiled configuration",
                ),
                RuntimeValidationFailure::Unavailable => (
                    DiagnosticCode::RuntimeValidatorUnavailable,
                    "runtime validator was unavailable; configuration was not committed",
                ),
            };
            report.push(Diagnostic::error(code, ConfigLayer::Compiled, "$", message));
            return Err(ConfigError::from_report(report));
        }

        let redacted_display_json = serde_json::to_string(&redact_value(&compiled, false))
            .map_err(|_| {
                ConfigError::from_diagnostic(Diagnostic::error(
                    DiagnosticCode::InvalidStructure,
                    ConfigLayer::Compiled,
                    "$",
                    "redacted configuration could not be serialized",
                ))
            })?;
        report.push(Diagnostic::validated());

        Ok(CompiledConfig {
            runtime_json,
            redacted_display_json,
            report,
        })
    }
}

/// Canonical configuration that has passed compiler and runtime validation.
///
/// Construction is private so runtime commit APIs can require this type and cannot
/// accidentally accept an unvalidated string.
#[derive(Clone)]
pub struct CompiledConfig {
    runtime_json: String,
    redacted_display_json: String,
    report: DiagnosticReport,
}

impl CompiledConfig {
    /// Canonical JSON for the managed runtime. This value may contain secrets.
    #[must_use]
    pub fn runtime_json(&self) -> &str {
        &self.runtime_json
    }

    /// Canonical JSON safe for ordinary diagnostics and user inspection.
    #[must_use]
    pub fn redacted_display_json(&self) -> &str {
        &self.redacted_display_json
    }

    /// Structured compilation and validation report.
    #[must_use]
    pub fn report(&self) -> &DiagnosticReport {
        &self.report
    }
}

impl fmt::Debug for CompiledConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledConfig")
            .field("redacted_display_json", &self.redacted_display_json)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

struct RedactedValue<'a>(&'a Value);

impl fmt::Debug for RedactedValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redact_value(self.0, false).fmt(formatter)
    }
}

fn parse_layer(source: &str, layer: ConfigLayer) -> Result<Value, ConfigError> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let parsed = StrictValue::deserialize(&mut deserializer).and_then(|value| {
        deserializer.end()?;
        Ok(value.0)
    });

    match parsed {
        Ok(value) => ensure_object(value, layer),
        Err(error) => {
            let duplicate = error.to_string().contains("duplicate object key");
            let code = if duplicate {
                DiagnosticCode::DuplicateObjectKey
            } else {
                DiagnosticCode::InvalidJson
            };
            Err(ConfigError::from_diagnostic(Diagnostic::error(
                code,
                layer,
                "$",
                format!(
                    "layer is not valid strict JSON (line {}, column {})",
                    error.line(),
                    error.column()
                ),
            )))
        }
    }
}

fn ensure_object(mut value: Value, layer: ConfigLayer) -> Result<Value, ConfigError> {
    if value.is_object() {
        sort_keys_recursive(&mut value);
        Ok(value)
    } else {
        Err(ConfigError::from_diagnostic(Diagnostic::error(
            DiagnosticCode::RootMustBeObject,
            layer,
            "$",
            "configuration layer root must be a JSON object",
        )))
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn validate_layer(value: &Value, layer: ConfigLayer, report: &mut DiagnosticReport) {
    validate_duplicate_tags(value, layer, "$", report);
}

fn validate_duplicate_tags(
    value: &Value,
    layer: ConfigLayer,
    path: &str,
    report: &mut DiagnosticReport,
) {
    match value {
        Value::Array(items) => {
            let mut tags = BTreeSet::new();
            let mut names = BTreeSet::new();
            for (index, item) in items.iter().enumerate() {
                for (identity_key, identities) in [("tag", &mut tags), ("name", &mut names)] {
                    if let Some(identity) = item.get(identity_key).and_then(Value::as_str)
                        && !identities.insert(identity)
                    {
                        report.push(Diagnostic::error(
                            DiagnosticCode::DuplicateTag,
                            layer,
                            format!("{path}[{index}].{identity_key}"),
                            "configuration array contains a duplicate tag or name identity",
                        ));
                    }
                }
                validate_duplicate_tags(item, layer, &format!("{path}[{index}]"), report);
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                validate_duplicate_tags(child, layer, &join_path(path, key), report);
            }
        }
        _ => {}
    }
}

fn reject_reserved_user_definitions(value: &Value, path: &str, report: &mut DiagnosticReport) {
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_reserved_user_definitions(item, &format!("{path}[{index}]"), report);
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = if key.starts_with(RESERVED_PREFIX) {
                    format!("{path}.<reserved>")
                } else {
                    join_path(path, key)
                };
                if key.starts_with(RESERVED_PREFIX) {
                    report.push(Diagnostic::error(
                        DiagnosticCode::ReservedNamespace,
                        ConfigLayer::UserProfile,
                        &child_path,
                        "user configuration may not define reserved FlowProbe object names",
                    ));
                }
                if is_definition_key(key)
                    && child
                        .as_str()
                        .is_some_and(|name| name.starts_with(RESERVED_PREFIX))
                {
                    report.push(Diagnostic::error(
                        DiagnosticCode::ReservedNamespace,
                        ConfigLayer::UserProfile,
                        &child_path,
                        "user configuration may not define reserved FlowProbe object names",
                    ));
                }
                reject_reserved_user_definitions(child, &child_path, report);
            }
        }
        _ => {}
    }
}

fn is_definition_key(key: &str) -> bool {
    matches!(key, "name" | "tag")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MergePolicy {
    UserProfile,
    RuntimeOverlay,
}

impl MergePolicy {
    fn layer(self) -> ConfigLayer {
        match self {
            Self::UserProfile => ConfigLayer::UserProfile,
            Self::RuntimeOverlay => ConfigLayer::RuntimeOverlay,
        }
    }
}

fn merge_value(
    target: &mut Value,
    incoming: &Value,
    policy: MergePolicy,
    path: &str,
    protected_context: bool,
    identity_context: bool,
    report: &mut DiagnosticReport,
) {
    if target == incoming {
        return;
    }

    let protected_context = protected_context || has_reserved_identity(target);
    if identity_context || (policy == MergePolicy::UserProfile && protected_context) {
        report.push(Diagnostic::error(
            DiagnosticCode::ProtectedObjectReplacement,
            policy.layer(),
            path,
            "configuration layer cannot modify a protected FlowProbe object",
        ));
        return;
    }

    match (&mut *target, incoming) {
        (Value::Object(target_object), Value::Object(incoming_object)) => {
            for (key, incoming_value) in incoming_object {
                let child_path = join_path(path, key);
                let child_protected = protected_context || key.starts_with(RESERVED_PREFIX);
                let child_identity = child_protected && is_definition_key(key);
                if let Some(target_value) = target_object.get_mut(key) {
                    merge_value(
                        target_value,
                        incoming_value,
                        policy,
                        &child_path,
                        child_protected,
                        child_identity,
                        report,
                    );
                } else if policy == MergePolicy::UserProfile && child_protected {
                    report.push(Diagnostic::error(
                        DiagnosticCode::ProtectedObjectReplacement,
                        policy.layer(),
                        &child_path,
                        "configuration layer cannot modify a protected FlowProbe object",
                    ));
                } else {
                    target_object.insert(key.clone(), incoming_value.clone());
                }
            }
        }
        (Value::Array(target_items), Value::Array(incoming_items)) => {
            for incoming_item in incoming_items {
                let matching_index = match resolve_identity_index(target_items, incoming_item) {
                    Ok(index) => index,
                    Err(()) => {
                        report.push(Diagnostic::error(
                            DiagnosticCode::IdentityConflict,
                            policy.layer(),
                            path,
                            "tag and name identities do not resolve consistently",
                        ));
                        continue;
                    }
                };

                if let Some(index) = matching_index {
                    merge_value(
                        &mut target_items[index],
                        incoming_item,
                        policy,
                        &format!("{path}[{index}]"),
                        protected_context,
                        false,
                        report,
                    );
                } else {
                    target_items.push(incoming_item.clone());
                }
            }
        }
        (target_value, incoming_value) => {
            if replaces_non_empty_container(target_value, incoming_value)
                || (protected_context
                    && is_container(target_value)
                    && !same_container_type(target_value, incoming_value))
            {
                report.push(Diagnostic::error(
                    DiagnosticCode::ProtectedObjectReplacement,
                    policy.layer(),
                    path,
                    "configuration layer cannot replace a non-empty or protected container",
                ));
            } else {
                *target_value = incoming_value.clone();
            }
        }
    }
}

fn resolve_identity_index(
    target_items: &[Value],
    incoming_item: &Value,
) -> Result<Option<usize>, ()> {
    let tag_index = identity_index(target_items, incoming_item, "tag");
    let name_index = identity_index(target_items, incoming_item, "name");

    if let (Some(tag_index), Some(name_index)) = (tag_index, name_index)
        && tag_index != name_index
    {
        return Err(());
    }

    let matching_index = tag_index.or(name_index);
    if let Some(index) = matching_index {
        let target_item = &target_items[index];
        for identity_key in ["tag", "name"] {
            if let (Some(target_identity), Some(incoming_identity)) = (
                target_item.get(identity_key),
                incoming_item.get(identity_key),
            ) && target_identity != incoming_identity
            {
                return Err(());
            }
        }
    }

    Ok(matching_index)
}

fn identity_index(
    target_items: &[Value],
    incoming_item: &Value,
    identity_key: &str,
) -> Option<usize> {
    incoming_item
        .get(identity_key)
        .and_then(Value::as_str)
        .and_then(|incoming_identity| {
            target_items.iter().position(|target_item| {
                target_item.get(identity_key).and_then(Value::as_str) == Some(incoming_identity)
            })
        })
}

fn has_reserved_identity(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        ["tag", "name"].into_iter().any(|identity_key| {
            object
                .get(identity_key)
                .and_then(Value::as_str)
                .is_some_and(|identity| identity.starts_with(RESERVED_PREFIX))
        })
    })
}

fn is_container(value: &Value) -> bool {
    matches!(value, Value::Object(_) | Value::Array(_))
}

fn same_container_type(left: &Value, right: &Value) -> bool {
    matches!(
        (left, right),
        (Value::Object(_), Value::Object(_)) | (Value::Array(_), Value::Array(_))
    )
}

fn replaces_non_empty_container(target: &Value, incoming: &Value) -> bool {
    let target_is_non_empty_container = match target {
        Value::Object(object) => !object.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => false,
    };
    target_is_non_empty_container && !same_container_type(target, incoming)
}

fn sort_keys_recursive(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                sort_keys_recursive(item);
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                sort_keys_recursive(child);
            }
            object.sort_keys();
        }
        _ => {}
    }
}

fn join_path(path: &str, key: &str) -> String {
    let segment = if key.starts_with(RESERVED_PREFIX) {
        "<reserved>"
    } else if is_sensitive_key(key) {
        "<sensitive>"
    } else if is_safe_diagnostic_key(key) {
        key
    } else {
        "<field>"
    };
    format!("{path}.{segment}")
}

fn is_safe_diagnostic_key(key: &str) -> bool {
    matches!(
        key,
        "dns"
            | "endpoints"
            | "experimental"
            | "inbounds"
            | "log"
            | "ntp"
            | "outbounds"
            | "route"
            | "rules"
            | "rule_set"
            | "servers"
            | "services"
            | "tag"
            | "type"
    )
}

fn redact_value(value: &Value, headers_context: bool) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| {
                    if headers_context {
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact_value(item, false)
                    }
                })
                .collect(),
        ),
        Value::Object(object) => {
            let mut redacted = Map::new();
            for (key, child) in object {
                let child_is_headers = is_headers_key(key);
                let child = if headers_context || is_sensitive_key(key) {
                    Value::String(REDACTED.to_owned())
                } else {
                    redact_value(child, child_is_headers)
                };
                redacted.insert(key.clone(), child);
            }
            Value::Object(redacted)
        }
        Value::String(_) if headers_context => Value::String(REDACTED.to_owned()),
        Value::String(value) => Value::String(redact_string(value)),
        _ if headers_context => Value::String(REDACTED.to_owned()),
        primitive => primitive.clone(),
    }
}

fn is_headers_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    normalized == "header" || normalized == "headers" || normalized.ends_with("headers")
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    matches!(
        normalized.as_str(),
        "auth"
            | "authentication"
            | "authkey"
            | "authstr"
            | "authorization"
            | "bearer"
            | "cookie"
            | "credentials"
            | "key"
            | "password"
            | "passwd"
            | "passphrase"
            | "proxyauthorization"
            | "presharedkey"
            | "secret"
            | "session"
            | "sessionid"
            | "setcookie"
            | "sid"
            | "sig"
            | "signature"
            | "token"
            | "userinfo"
            | "user"
            | "username"
            | "uuid"
    ) || normalized.contains("accesskey")
        || normalized.contains("apikey")
        || normalized.contains("authorization")
        || normalized.contains("credential")
        || normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("passphrase")
        || normalized.contains("privatekey")
        || normalized.contains("presharedkey")
        || normalized.contains("secret")
        || normalized.contains("signature")
        || (normalized.contains("token")
            && !normalized.ends_with("tokenendpoint")
            && !normalized.ends_with("tokenurl"))
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn redact_string(value: &str) -> String {
    let trimmed = value.trim();
    let lowered = trimmed.to_ascii_lowercase();
    if trimmed
        .split_once(':')
        .is_some_and(|(header_name, _)| is_sensitive_key(header_name))
        || lowered.starts_with("authorization:")
        || lowered.starts_with("proxy-authorization:")
        || lowered.starts_with("cookie:")
        || lowered.starts_with("set-cookie:")
        || lowered.starts_with("bearer ")
        || lowered.starts_with("basic ")
        || looks_like_jwt(trimmed)
    {
        return REDACTED.to_owned();
    }

    let mut redacted = value.to_owned();

    if let Some(scheme_end) = value.find("://") {
        let scheme = value[..scheme_end].to_ascii_lowercase();
        let authority_start = scheme_end + 3;
        let authority_end = value[authority_start..]
            .find(['/', '?', '#'])
            .map_or(value.len(), |offset| authority_start + offset);
        let authority = &value[authority_start..authority_end];

        if let Some(at) = authority.rfind('@') {
            redacted.replace_range(authority_start..authority_start + at, REDACTED);
        } else if matches!(scheme.as_str(), "ss" | "ssr" | "vmess") {
            redacted.replace_range(authority_start..authority_end, REDACTED);
        }
    }

    redact_parameter_representations(&redacted)
}

fn redact_parameter_representations(value: &str) -> String {
    let mut redacted = value.to_owned();

    if let Some(query_start) = redacted.find('?') {
        let query_value_start = query_start + 1;
        let query_end = redacted[query_value_start..]
            .find('#')
            .map_or(redacted.len(), |offset| query_value_start + offset);
        let query = redact_parameter_pairs(&redacted[query_value_start..query_end]);
        redacted.replace_range(query_value_start..query_end, &query);
    }

    if let Some(fragment_start) = redacted.find('#') {
        let fragment_value_start = fragment_start + 1;
        let fragment = redact_parameter_pairs(&redacted[fragment_value_start..]);
        redacted.replace_range(fragment_value_start.., &fragment);
    }

    if !redacted.contains(['?', '#']) && redacted.contains('=') {
        return redact_parameter_pairs(&redacted);
    }

    redacted
}

fn redact_parameter_pairs(value: &str) -> String {
    let mut redacted_parts = Vec::new();

    for part in value.split('&') {
        if let Some((key, parameter_value)) = part.split_once('=') {
            if is_sensitive_key(&percent_decode_component(key))
                || looks_like_jwt(&percent_decode_component(parameter_value))
            {
                redacted_parts.push(format!("{key}={REDACTED}"));
            } else {
                redacted_parts.push(part.to_owned());
            }
        } else if looks_like_jwt(&percent_decode_component(part)) {
            redacted_parts.push(REDACTED.to_owned());
        } else {
            redacted_parts.push(part.to_owned());
        }
    }
    redacted_parts.join("&")
}

fn percent_decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            part.len() >= 8
                && part.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
        })
}
