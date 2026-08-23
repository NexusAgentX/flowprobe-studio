use std::sync::{Arc, Mutex};

use flowprobe_config_compiler::{
    ConfigCompiler, ConfigLayer, DiagnosticCode, DiagnosticSeverity, REDACTED,
    RuntimeConfigValidator, RuntimeOverlay, RuntimeValidationFailure, SystemBase, UserProfile,
};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
struct AcceptingValidator;

impl RuntimeConfigValidator for AcceptingValidator {
    fn validate(&self, _canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        Ok(())
    }
}

struct RejectingValidator(RuntimeValidationFailure);

impl RuntimeConfigValidator for RejectingValidator {
    fn validate(&self, _canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        Err(self.0)
    }
}

struct RecordingValidator {
    observed: Arc<Mutex<Option<String>>>,
}

impl RuntimeConfigValidator for RecordingValidator {
    fn validate(&self, canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        *self
            .observed
            .lock()
            .expect("recording validator mutex should not be poisoned") =
            Some(canonical_runtime_json.to_owned());
        Ok(())
    }
}

fn system_base(source: &str) -> SystemBase {
    SystemBase::parse(source).expect("system base should parse")
}

fn user_profile(source: &str) -> UserProfile {
    UserProfile::parse(source).expect("user profile should parse")
}

fn runtime_overlay(source: &str) -> RuntimeOverlay {
    RuntimeOverlay::parse(source).expect("runtime overlay should parse")
}

fn empty_system() -> SystemBase {
    system_base("{}")
}

fn empty_user_profile() -> UserProfile {
    user_profile("{}")
}

fn empty_overlay() -> RuntimeOverlay {
    runtime_overlay("{}")
}

#[test]
fn compilation_is_canonical_and_preserves_ordinary_sing_box_capabilities() {
    let system = system_base(
        r#"{
          "route": {"rules": [{"process_name": ["flowprobe"], "outbound": "__flowprobe_direct"}]},
          "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
          "inbounds": [{"listen_port": 0, "type": "mixed", "tag": "__flowprobe_capture"}]
        }"#,
    );
    let user_a = user_profile(
        r#"{
          "experimental": {"cache_file": {"enabled": true}},
          "outbounds": [
            {"type": "socks", "tag": "home", "server": "proxy.example", "server_port": 1080},
            {"tag": "select", "type": "selector", "outbounds": ["home"]},
            {"url": "https://example.test/ping", "type": "urltest", "tag": "fast", "outbounds": ["home"]}
          ],
          "route": {"rules": [{"domain_suffix": ["example.com"], "outbound": "select"}]},
          "dns": {
            "rules": [{"domain_suffix": ["example.com"], "server": "secure"}],
            "servers": [{"server": "1.1.1.1", "type": "https", "tag": "secure"}]
          },
          "future_native_option": {"retained": [3, 2, 1]}
        }"#,
    );
    let user_b = user_profile(
        r#"{
          "future_native_option": {"retained": [3, 2, 1]},
          "dns": {
            "servers": [{"tag": "secure", "type": "https", "server": "1.1.1.1"}],
            "rules": [{"server": "secure", "domain_suffix": ["example.com"]}]
          },
          "route": {"rules": [{"outbound": "select", "domain_suffix": ["example.com"]}]},
          "outbounds": [
            {"server_port": 1080, "server": "proxy.example", "tag": "home", "type": "socks"},
            {"outbounds": ["home"], "type": "selector", "tag": "select"},
            {"outbounds": ["home"], "tag": "fast", "type": "urltest", "url": "https://example.test/ping"}
          ],
          "experimental": {"cache_file": {"enabled": true}}
        }"#,
    );
    let overlay = runtime_overlay(
        r#"{
          "inbounds": [{"tag": "__flowprobe_capture", "listen_port": 18181}],
          "runtime_state": {"capture_mode": "direct", "physical_interface": "en0"}
        }"#,
    );
    let compiler = ConfigCompiler::new(AcceptingValidator);

    let first = compiler
        .compile(&system, &user_a, &overlay)
        .expect("valid layers should compile");
    let second = compiler
        .compile(&system, &user_b, &overlay)
        .expect("equivalent normalized layers should compile");

    assert_eq!(first.runtime_json(), second.runtime_json());
    assert!(!first.runtime_json().contains("\n"));

    let compiled: Value =
        serde_json::from_str(first.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(compiled["inbounds"][0]["listen_port"], 18181);
    assert_eq!(compiled["inbounds"][0]["type"], "mixed");
    assert_eq!(compiled["outbounds"][0]["tag"], "__flowprobe_direct");
    assert_eq!(compiled["outbounds"][1]["tag"], "home");
    assert_eq!(compiled["outbounds"][2]["type"], "selector");
    assert_eq!(compiled["outbounds"][3]["type"], "urltest");
    assert_eq!(compiled["dns"]["servers"][0]["tag"], "secure");
    assert_eq!(compiled["route"]["rules"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        compiled["future_native_option"]["retained"],
        json!([3, 2, 1])
    );
    assert_eq!(compiled["runtime_state"]["physical_interface"], "en0");
    assert_eq!(
        first.report().diagnostics()[0].code(),
        DiagnosticCode::ConfigValidated
    );
}

#[test]
fn user_reserved_definition_keys_tags_and_nested_names_are_rejected_without_echoing_values() {
    let user = user_profile(
        r#"{
          "__flowprobe_hidden-secret": {"password": "do-not-echo"},
          "outbounds": [{"type": "direct", "tag": "__flowprobe_collision"}],
          "experimental": {"nested": {"name": "__flowprobe_named-object"}}
        }"#,
    );

    let error = ConfigCompiler::new(AcceptingValidator)
        .compile(&empty_system(), &user, &empty_overlay())
        .expect_err("reserved user names must fail");

    assert!(error.report().diagnostics().iter().all(|diagnostic| {
        diagnostic.code() == DiagnosticCode::ReservedNamespace
            && diagnostic.layer() == ConfigLayer::UserProfile
            && diagnostic.severity() == DiagnosticSeverity::Error
    }));
    let serialized = serde_json::to_string(error.report()).expect("report should serialize");
    for forbidden in [
        "hidden-secret",
        "do-not-echo",
        "__flowprobe_collision",
        "__flowprobe_named-object",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn reserved_prefix_in_password_comment_and_route_reference_is_not_a_definition() {
    let system = system_base(
        r#"{
          "comment": "__flowprobe_system_comment",
          "route": {"final": "__flowprobe_direct"},
          "outbounds": [{"type":"direct","tag":"__flowprobe_direct"}]
        }"#,
    );
    let user = user_profile(
        r#"{
          "comment": "__flowprobe_comment_literal",
          "password": "__flowprobe_password_literal",
          "route": {
            "final": "__flowprobe_user_fallback",
            "rules": [{"outbound": "__flowprobe_direct"}]
          }
        }"#,
    );

    let compiled = ConfigCompiler::new(AcceptingValidator)
        .compile(&system, &user, &empty_overlay())
        .expect("ordinary values and references are not reserved-name definitions");

    assert!(
        compiled
            .runtime_json()
            .contains("__flowprobe_password_literal")
    );
    assert!(
        !compiled
            .redacted_display_json()
            .contains("__flowprobe_password_literal")
    );
    assert!(
        compiled
            .redacted_display_json()
            .contains("__flowprobe_comment_literal")
    );
    assert!(
        compiled
            .redacted_display_json()
            .contains("__flowprobe_direct")
    );
    assert!(
        compiled
            .runtime_json()
            .contains("__flowprobe_user_fallback")
    );
}

#[test]
fn user_cannot_mutate_a_protected_object_without_repeating_its_identity() {
    let system = system_base(
        r#"{
          "by_name": {
            "name": "__flowprobe_internal",
            "type": "mixed",
            "listen_port": 0
          },
          "by_tag": {
            "tag": "__flowprobe_capture",
            "type": "mixed",
            "listen_port": 0
          }
        }"#,
    );

    for user in [
        user_profile(r#"{"by_name":{"type":"socks"}}"#),
        user_profile(r#"{"by_name":{"listen_port":18180}}"#),
        user_profile(r#"{"by_name":{"future_user_field":true}}"#),
        user_profile(r#"{"by_tag":{"type":"socks"}}"#),
        user_profile(r#"{"by_tag":{"listen_port":18181}}"#),
        user_profile(r#"{"by_tag":{"future_user_field":true}}"#),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &user, &empty_overlay())
            .expect_err("a user cannot recursively mutate a protected definition");
        assert!(error.report().diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement
                && diagnostic.layer() == ConfigLayer::UserProfile
        }));
    }
}

#[test]
fn user_parent_replacement_and_null_cannot_delete_protected_objects() {
    let system = system_base(
        r#"{
          "inbounds": [{"type": "mixed", "tag": "__flowprobe_capture", "listen_port": 0}],
          "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
          "route": {"rules": [{"outbound": "__flowprobe_direct"}]},
          "dns": {"servers": [{"type": "local", "tag": "__flowprobe_dns"}]}
        }"#,
    );

    let preserved = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &user_profile(r#"{"outbounds":[],"route":{"rules":[]},"dns":{"servers":[]}}"#),
            &empty_overlay(),
        )
        .expect("empty user collections must not delete protected objects");
    let preserved: Value =
        serde_json::from_str(preserved.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(preserved["outbounds"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        preserved["route"]["rules"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        preserved["dns"]["servers"].as_array().map(Vec::len),
        Some(1)
    );

    for user in [
        user_profile(r#"{"outbounds": null}"#),
        user_profile(r#"{"outbounds": "replacement"}"#),
        user_profile(r#"{"route": null}"#),
        user_profile(r#"{"route": {"rules": null}}"#),
        user_profile(r#"{"route": "replacement"}"#),
        user_profile(r#"{"dns": null}"#),
        user_profile(r#"{"dns": {"servers": "replacement"}}"#),
        user_profile(r#"{"dns": "replacement"}"#),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &user, &empty_overlay())
            .expect_err("a protected parent must not be replaceable");
        assert!(
            error.report().diagnostics().iter().any(|diagnostic| {
                diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement
            })
        );
    }
}

#[test]
fn runtime_overlay_preserves_protected_parents_and_allows_matching_object_updates() {
    let system = system_base(
        r#"{
          "internal": {"name": "__flowprobe_internal", "type": "mixed", "listen_port": 0},
          "inbounds": [{"type": "mixed", "tag": "__flowprobe_capture", "listen_port": 0}],
          "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
          "route": {"rules": [{"outbound": "__flowprobe_direct"}]},
          "dns": {"servers": [{"type": "local", "tag": "__flowprobe_dns"}]}
        }"#,
    );

    let preserved = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(r#"{"outbounds":[],"route":{"rules":[]},"dns":{"servers":[]}}"#),
        )
        .expect("empty runtime collections must not delete protected objects");
    let preserved: Value =
        serde_json::from_str(preserved.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(preserved["outbounds"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        preserved["route"]["rules"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        preserved["dns"]["servers"].as_array().map(Vec::len),
        Some(1)
    );

    let updated = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(
                r#"{
                  "internal": {"name": "__flowprobe_internal", "listen_port": 18180},
                  "inbounds": [{
                    "tag": "__flowprobe_capture",
                    "listen_port": 18181,
                    "future_runtime_field": {"enabled": true}
                  }]
                }"#,
            ),
        )
        .expect("matching identity and ephemeral port updates must be allowed");
    let updated: Value =
        serde_json::from_str(updated.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(updated["internal"]["listen_port"], 18180);
    assert_eq!(updated["inbounds"][0]["listen_port"], 18181);
    assert_eq!(updated["inbounds"][0]["tag"], "__flowprobe_capture");
    assert_eq!(
        updated["inbounds"][0]["future_runtime_field"]["enabled"],
        true
    );

    for overlay in [
        runtime_overlay(r#"{"outbounds": null}"#),
        runtime_overlay(r#"{"outbounds": "replacement"}"#),
        runtime_overlay(r#"{"route": null}"#),
        runtime_overlay(r#"{"route": {"rules": null}}"#),
        runtime_overlay(r#"{"route": {"rules": "replacement"}}"#),
        runtime_overlay(r#"{"route": "replacement"}"#),
        runtime_overlay(r#"{"dns": null}"#),
        runtime_overlay(r#"{"dns": {"servers": null}}"#),
        runtime_overlay(r#"{"dns": {"servers": "replacement"}}"#),
        runtime_overlay(r#"{"dns": "replacement"}"#),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &empty_user_profile(), &overlay)
            .expect_err("runtime overlay cannot replace a protected parent");
        assert!(
            error.report().diagnostics().iter().any(|diagnostic| {
                diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement
            })
        );
    }

    let error = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(r#"{"internal":{"name":"__flowprobe_renamed"}}"#),
        )
        .expect_err("runtime overlay cannot rename a protected identity");
    assert!(
        error
            .report()
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement })
    );
}

#[test]
fn runtime_overlay_matches_name_identities_in_place_and_preserves_protected_identity() {
    let system = system_base(
        r#"{
          "services": [
            {
              "name": "__flowprobe_runtime_service",
              "type": "mixed",
              "listen_port": 0
            },
            {"name": "ordinary_service", "value": 1}
          ],
          "inbounds": [{
            "tag": "__flowprobe_capture",
            "name": "__flowprobe_original_name",
            "listen_port": 0
          }]
        }"#,
    );
    let compiled = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(
                r#"{
                  "services": [
                    {"name": "__flowprobe_runtime_service", "listen_port": 18180},
                    {"name": "ordinary_service", "value": 2}
                  ]
                }"#,
            ),
        )
        .expect("runtime objects with matching names must update in place");
    let compiled: Value =
        serde_json::from_str(compiled.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(compiled["services"].as_array().map(Vec::len), Some(2));
    assert_eq!(compiled["services"][0]["listen_port"], 18180);
    assert_eq!(compiled["services"][0]["type"], "mixed");
    assert_eq!(compiled["services"][1]["value"], 2);

    let error = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(
                r#"{
                  "inbounds": [{
                    "tag": "__flowprobe_capture",
                    "name": "__flowprobe_renamed"
                  }]
                }"#,
            ),
        )
        .expect_err("runtime matching must not change a protected name identity");
    assert!(error.report().diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == DiagnosticCode::IdentityConflict
            && diagnostic.layer() == ConfigLayer::RuntimeOverlay
    }));
}

#[test]
fn array_identity_resolution_rejects_cross_matches_and_preserves_secondary_identities() {
    let system = system_base(
        r#"{
          "services": [
            {"tag": "tag_a", "name": "name_a", "value": 1},
            {"tag": "tag_b", "name": "name_b", "value": 2},
            {
              "tag": "__flowprobe_protected_tag",
              "name": "__flowprobe_protected_name",
              "value": 3
            },
            {"tag": "tag_only", "value": 4},
            {"tag": "__flowprobe_protected_tag_only", "value": 5}
          ]
        }"#,
    );

    let user_error = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &user_profile(r#"{"services":[{"tag":"tag_b","name":"name_a","value":20}]}"#),
            &empty_overlay(),
        )
        .expect_err("user tag/name identities cannot resolve to different target items");
    assert!(user_error.report().diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == DiagnosticCode::IdentityConflict
            && diagnostic.layer() == ConfigLayer::UserProfile
    }));

    for overlay in [
        runtime_overlay(r#"{"services":[{"tag":"tag_b","name":"name_a","value":20}]}"#),
        runtime_overlay(r#"{"services":[{"tag":"tag_a","name":"ordinary_new_name","value":20}]}"#),
        runtime_overlay(
            r#"{"services":[{"tag":"__flowprobe_protected_tag","name":"__flowprobe_protected_new_name","value":30}]}"#,
        ),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &empty_user_profile(), &overlay)
            .expect_err("an existing secondary identity cannot be changed");
        assert!(error.report().diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == DiagnosticCode::IdentityConflict
                && diagnostic.layer() == ConfigLayer::RuntimeOverlay
        }));
    }

    let compiled = ConfigCompiler::new(AcceptingValidator)
        .compile(
            &system,
            &empty_user_profile(),
            &runtime_overlay(
                r#"{
                  "services": [
                    {"tag": "tag_b", "value": 20},
                    {"tag": "tag_only", "name": "added_name", "value": 40},
                    {
                      "tag": "__flowprobe_protected_tag_only",
                      "name": "__flowprobe_added_name",
                      "value": 50
                    }
                  ]
                }"#,
            ),
        )
        .expect("a missing secondary identity may be omitted or added without collision");
    let compiled: Value =
        serde_json::from_str(compiled.runtime_json()).expect("compiled JSON should parse");
    assert_eq!(compiled["services"].as_array().map(Vec::len), Some(5));
    assert_eq!(compiled["services"][1]["name"], "name_b");
    assert_eq!(compiled["services"][1]["value"], 20);
    assert_eq!(compiled["services"][3]["name"], "added_name");
    assert_eq!(compiled["services"][3]["value"], 40);
    assert_eq!(compiled["services"][4]["name"], "__flowprobe_added_name");
    assert_eq!(compiled["services"][4]["value"], 50);
}

#[test]
fn non_empty_containers_and_reserved_key_objects_fail_closed_on_parent_replacement() {
    let system = system_base(
        r#"{
          "ordinary_object": {"enabled": true},
          "ordinary_array": [{"name": "ordinary", "enabled": true}],
          "__flowprobe_empty_runtime_object": {}
        }"#,
    );

    for user in [
        user_profile(r#"{"ordinary_object":null}"#),
        user_profile(r#"{"ordinary_object":"replacement"}"#),
        user_profile(r#"{"ordinary_object":[]}"#),
        user_profile(r#"{"ordinary_array":null}"#),
        user_profile(r#"{"ordinary_array":"replacement"}"#),
        user_profile(r#"{"ordinary_array":{}}"#),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &user, &empty_overlay())
            .expect_err("user parent replacement must fail closed");
        assert!(error.report().diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement
                && diagnostic.layer() == ConfigLayer::UserProfile
        }));
    }

    for overlay in [
        runtime_overlay(r#"{"ordinary_object":null}"#),
        runtime_overlay(r#"{"ordinary_object":"replacement"}"#),
        runtime_overlay(r#"{"ordinary_object":[]}"#),
        runtime_overlay(r#"{"ordinary_array":null}"#),
        runtime_overlay(r#"{"ordinary_array":"replacement"}"#),
        runtime_overlay(r#"{"ordinary_array":{}}"#),
        runtime_overlay(r#"{"__flowprobe_empty_runtime_object":null}"#),
    ] {
        let error = ConfigCompiler::new(AcceptingValidator)
            .compile(&system, &empty_user_profile(), &overlay)
            .expect_err("runtime parent replacement must fail closed");
        assert!(error.report().diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == DiagnosticCode::ProtectedObjectReplacement
                && diagnostic.layer() == ConfigLayer::RuntimeOverlay
        }));
    }
}

#[test]
fn strict_inputs_reject_malformed_json_duplicate_keys_and_non_object_roots() {
    let malformed =
        UserProfile::parse(r#"{"outbounds": [}"#).expect_err("malformed JSON should fail");
    assert_eq!(
        malformed.report().diagnostics()[0].code(),
        DiagnosticCode::InvalidJson
    );

    let duplicate = UserProfile::parse(r#"{"outbounds": [], "outbounds": null}"#)
        .expect_err("duplicate object keys should fail");
    assert_eq!(
        duplicate.report().diagnostics()[0].code(),
        DiagnosticCode::DuplicateObjectKey
    );

    let array = UserProfile::parse("[]").expect_err("layer root must be an object");
    assert_eq!(
        array.report().diagnostics()[0].code(),
        DiagnosticCode::RootMustBeObject
    );
}

#[test]
fn duplicate_tags_are_rejected_before_runtime_schema_validation() {
    let duplicate_tags = user_profile(
        r#"{
          "outbounds": [
            {"type": "direct", "tag": "same"},
            {"type": "socks", "tag": "same", "server": "proxy.example", "server_port": 1080}
          ]
        }"#,
    );
    let error = ConfigCompiler::new(AcceptingValidator)
        .compile(&empty_system(), &duplicate_tags, &empty_overlay())
        .expect_err("duplicate tags must fail");
    assert!(
        error
            .report()
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code() == DiagnosticCode::DuplicateTag })
    );

    let duplicate_names = runtime_overlay(
        r#"{
          "services": [
            {"name": "same", "port": 1},
            {"name": "same", "port": 2}
          ]
        }"#,
    );
    let error = ConfigCompiler::new(AcceptingValidator)
        .compile(&empty_system(), &empty_user_profile(), &duplicate_names)
        .expect_err("duplicate names used for array matching must fail");
    assert!(
        error
            .report()
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code() == DiagnosticCode::DuplicateTag })
    );
}

#[test]
fn runtime_validator_remains_authoritative_for_sing_box_schema_versions() {
    for user in [
        user_profile(r#"{"outbounds": "not-an-array"}"#),
        user_profile(r#"{"outbounds": [{}]}"#),
        user_profile(r#"{"dns": {"servers": ["not-an-object"]}}"#),
        user_profile(r#"{"route": {"rules": {}}}"#),
    ] {
        let error = ConfigCompiler::new(RejectingValidator(RuntimeValidationFailure::Rejected))
            .compile(&empty_system(), &user, &empty_overlay())
            .expect_err("runtime schema validation rejection must fail compilation");
        assert!(
            error.report().diagnostics().iter().any(|diagnostic| {
                diagnostic.code() == DiagnosticCode::RuntimeValidationRejected
            })
        );
    }
}

#[test]
fn display_and_debug_forms_redact_nested_credentials_headers_and_uri_secrets() {
    let user = user_profile(
        r#"{
          "outbounds": [{
            "type": "socks",
            "tag": "private-proxy",
            "server": "proxy.example",
            "server_port": 1080,
            "user": "ssh-user",
            "username": "proxy-user",
            "password": "proxy-password",
            "uuid": "11111111-2222-3333-4444-555555555555",
            "tls": {
              "private_key": "private-key-material",
              "pre_shared_key": "pre-shared-key-material",
              "public_key": "public-key-material"
            },
            "auth_str": "auth-string-secret",
            "secret_access_key": "access-key-secret",
            "token_endpoint": "https://auth.example/token",
            "transport": {"headers": {
              "Authorization": "Bearer authorization-secret",
              "Cookie": "session=cookie-secret",
              "X-Custom-Auth": "custom-header-secret",
              "User-Agent": "header-value-is-redacted-too"
            }},
            "nested": {"credentials": {"client_secret": "nested-secret"}},
            "api_url": "https://uri-user:uri-password@example.test/api?access_token=query-token&password=query-password&visible=yes",
            "encoded_query_url": "https://example.test/api?api%5Ftoken=encoded-query-token&visible=yes",
            "relative_url": "/api?token=relative-query-token&visible=yes",
            "fragment_url": "https://example.test/callback#access_token=fragment-token&visible=yes",
            "bare_query": "password=bare-query-password&visible=yes",
            "raw_headers": "X-Api-Key: raw-header-secret",
            "share_link": "ss://encoded-credential-payload",
            "opaque_ssr_link": "ssr://opaque-ssr-secret",
            "header_line": "Authorization: Bearer line-secret",
            "jwt_like": "abcdefgh.ijklmnop.qrstuvwx",
            "query_assertion": "https://example.test/callback?assertion=queryjwtA.queryjwtB.queryjwtC&visible=yes",
            "fragment_assertion": "https://example.test/callback#assertion=fragjwtAA.fragjwtBB.fragjwtCC&visible=yes",
            "encoded_assertion": "https://example.test/callback?assertion=encodedA%2EencodedB%2EencodedC&visible=yes"
          }]
        }"#,
    );
    let compiler = ConfigCompiler::new(AcceptingValidator);
    let compiled = compiler
        .compile(&empty_system(), &user, &empty_overlay())
        .expect("credential-bearing config should compile");
    let diagnostics =
        serde_json::to_string(compiled.report()).expect("diagnostics should serialize");

    for expected_runtime_secret in [
        "proxy-user",
        "ssh-user",
        "proxy-password",
        "authorization-secret",
        "cookie-secret",
        "custom-header-secret",
        "nested-secret",
        "uri-user",
        "uri-password",
        "query-token",
        "query-password",
        "encoded-query-token",
        "encoded-credential-payload",
        "opaque-ssr-secret",
        "line-secret",
        "abcdefgh.ijklmnop.qrstuvwx",
        "queryjwtA.queryjwtB.queryjwtC",
        "fragjwtAA.fragjwtBB.fragjwtCC",
        "encodedA%2EencodedB%2EencodedC",
        "private-key-material",
        "pre-shared-key-material",
        "auth-string-secret",
        "relative-query-token",
        "fragment-token",
        "bare-query-password",
        "access-key-secret",
        "raw-header-secret",
    ] {
        assert!(compiled.runtime_json().contains(expected_runtime_secret));
        assert!(
            !compiled
                .redacted_display_json()
                .contains(expected_runtime_secret)
        );
        assert!(!format!("{compiled:?}").contains(expected_runtime_secret));
        assert!(!format!("{user:?}").contains(expected_runtime_secret));
        assert!(!diagnostics.contains(expected_runtime_secret));
    }

    assert!(compiled.redacted_display_json().contains(REDACTED));
    let _: Value = serde_json::from_str(compiled.redacted_display_json())
        .expect("redacted display must remain valid JSON");
    assert!(
        compiled
            .redacted_display_json()
            .contains("public-key-material")
    );
    assert!(compiled.redacted_display_json().contains("visible=yes"));
    assert!(
        compiled
            .redacted_display_json()
            .contains("https://auth.example/token")
    );
    assert!(!diagnostics.contains("proxy-password"));
    assert!(!diagnostics.contains("authorization-secret"));
}

#[test]
fn runtime_validation_is_mandatory_and_precedes_artifact_construction() {
    for (failure, expected_code) in [
        (
            RuntimeValidationFailure::Rejected,
            DiagnosticCode::RuntimeValidationRejected,
        ),
        (
            RuntimeValidationFailure::Unavailable,
            DiagnosticCode::RuntimeValidatorUnavailable,
        ),
    ] {
        let error = ConfigCompiler::new(RejectingValidator(failure))
            .compile(
                &empty_system(),
                &user_profile(
                    r#"{"outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"password":"must-not-leak"}]}"#,
                ),
                &empty_overlay(),
            )
            .expect_err("runtime validation failure must prevent a compiled artifact");
        assert_eq!(error.report().diagnostics()[0].code(), expected_code);
        let report = serde_json::to_string(error.report()).expect("report should serialize");
        assert!(!report.contains("must-not-leak"));
        assert!(!format!("{error:?}").contains("must-not-leak"));
    }
}

#[test]
fn runtime_validator_receives_the_canonical_secret_bearing_configuration() {
    let observed = Arc::new(Mutex::new(None));
    let compiler = ConfigCompiler::new(RecordingValidator {
        observed: Arc::clone(&observed),
    });
    let compiled = compiler
        .compile(
            &empty_system(),
            &user_profile(
                r#"{"outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"password":"runtime-only-secret"}]}"#,
            ),
            &empty_overlay(),
        )
        .expect("recording validator should accept the configuration");
    let observed = observed
        .lock()
        .expect("recording validator mutex should not be poisoned")
        .clone()
        .expect("validator should receive one configuration");

    assert_eq!(observed, compiled.runtime_json());
    assert!(observed.contains("runtime-only-secret"));
    assert!(
        !compiled
            .redacted_display_json()
            .contains("runtime-only-secret")
    );
}
