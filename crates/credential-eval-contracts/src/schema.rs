//! Document schema tags and JSON Schema generation.
//!
//! Every top-level document carries a `schema` field whose value is a fixed
//! string naming the document type and its schema major version. Schema
//! versions are independent of both the crate version and
//! [`crate::PROTOCOL_VERSION`].
//!
//! The committed JSON Schemas under `schemas/` are generated from these types
//! by [`all_schemas`]; `tests/schema_drift.rs` fails when they differ.
//! Regenerate with `UPDATE_SCHEMAS=1 cargo test -p credential-eval-contracts --test schema_drift`.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! schema_tag {
    ($(#[$meta:meta])* $name:ident = $value:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            /// The literal tag value.
            pub const VALUE: &'static str = $value;
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let found = String::deserialize(deserializer)?;
                if found == $value {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(crate::ContractError::SchemaMismatch {
                        expected: $value,
                        found,
                    }))
                }
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "const": $value })
            }
        }
    };
}

schema_tag!(
    /// Tag of [`crate::corpus::CorpusSnapshot`] documents.
    CorpusSnapshotSchema = "credential-eval/corpus-snapshot/v1"
);
schema_tag!(
    /// Tag of [`crate::config::RunConfig`] documents.
    RunConfigSchema = "credential-eval/run-config/v1"
);
schema_tag!(
    /// Tag of [`crate::observation::ObservationSet`] documents.
    ObservationSetSchema = "credential-eval/observation-set/v1"
);
schema_tag!(
    /// Tag of [`crate::artifact::RunArtifact`] documents.
    RunArtifactSchema = "credential-eval/run-artifact/v1"
);

schema_tag!(
    /// Tag of [`crate::performance::PerformanceConfig`] documents (ADR 0002).
    PerformanceConfigSchema = "credential-eval/performance-config/v1"
);
schema_tag!(
    /// Tag of [`crate::performance::PerformanceArtifact`] documents (ADR 0002).
    PerformanceArtifactSchema = "credential-eval/performance-artifact/v1"
);

schema_tag!(
    /// Tag of [`crate::performance::DirectionConfirmation`] documents (ADR 0002).
    DirectionConfirmationSchema = "credential-eval/direction-confirmation/v1"
);

/// Base URI used for the `$id` of committed schemas.
pub const SCHEMA_ID_BASE: &str = "https://github.com/redact-secret/credential-eval/schemas/";

fn schema_for<T: JsonSchema>(file: &str, title: &str) -> Schema {
    let mut generator = SchemaGenerator::new(SchemaSettings::draft2020_12());
    let mut schema = generator.root_schema_for::<T>();
    schema.insert("$id".into(), format!("{SCHEMA_ID_BASE}{file}").into());
    schema.insert("title".into(), title.into());
    schema
}

/// Every committed schema: `(file name under schemas/, schema)`, in a fixed order.
pub fn all_schemas() -> Vec<(&'static str, Schema)> {
    vec![
        (
            "corpus-snapshot-v1.schema.json",
            schema_for::<crate::corpus::CorpusSnapshot>(
                "corpus-snapshot-v1.schema.json",
                "CorpusSnapshot",
            ),
        ),
        (
            "run-config-v1.schema.json",
            schema_for::<crate::config::RunConfig>("run-config-v1.schema.json", "RunConfig"),
        ),
        (
            "observation-set-v1.schema.json",
            schema_for::<crate::observation::ObservationSet>(
                "observation-set-v1.schema.json",
                "ObservationSet",
            ),
        ),
        (
            "run-artifact-v1.schema.json",
            schema_for::<crate::artifact::RunArtifact>(
                "run-artifact-v1.schema.json",
                "RunArtifact",
            ),
        ),
        (
            "performance-config-v1.schema.json",
            schema_for::<crate::performance::PerformanceConfig>(
                "performance-config-v1.schema.json",
                "PerformanceConfig",
            ),
        ),
        (
            "performance-artifact-v1.schema.json",
            schema_for::<crate::performance::PerformanceArtifact>(
                "performance-artifact-v1.schema.json",
                "PerformanceArtifact",
            ),
        ),
        (
            "direction-confirmation-v1.schema.json",
            schema_for::<crate::performance::DirectionConfirmation>(
                "direction-confirmation-v1.schema.json",
                "DirectionConfirmation",
            ),
        ),
    ]
}

/// Render a schema exactly as committed: pretty JSON with a trailing newline.
pub fn render(schema: &Schema) -> String {
    let mut text = serde_json::to_string_pretty(schema).expect("schema serializes");
    text.push('\n');
    text
}
