//! Scanner label → credential family mapping (adapter-owned data).
//!
//! Exact port of the legacy `scanners/families.mjs` (`familyMappingVersion = 2`)
//! at the pinned oracle commit. The mapping is deliberately partial: a label
//! that is not listed yields no family and is never guessed from fixture
//! expectations. The family is an observation attached to a finding; it never
//! changes an outcome except through the kernel's twin scoping.
//!
//! The comments in the legacy file explain why each label maps where it does;
//! they are not repeated here. Changing a table is an adapter change: bump
//! [`FAMILY_MAPPING_VERSION`] and the affected adapters' versions.

use credential_eval_contracts::ids::{NativeLabel, UNRECOGNIZED_NATIVE_LABEL};

use crate::openredaction_labels::OPEN_REDACTION_1_1_5_TYPES;

/// Version of the label → family tables (legacy `familyMappingVersion`).
pub const FAMILY_MAPPING_VERSION: u32 = 2;

/// Which native label table to consult.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelTable {
    /// Gitleaks `RuleID`.
    Gitleaks,
    /// TruffleHog `DetectorName`.
    Trufflehog,
    /// flare-redact detector id.
    FlareRedact,
    /// OpenRedaction pattern type.
    OpenRedaction,
    /// Redact Secret detector id (+ finding type for arrival families).
    RedactSecret,
}

/// Family ids that a Redact Secret detector id maps to verbatim
/// (legacy `families`, `families.mjs:4-33`).
const DETECTOR_FAMILIES: &[&str] = &[
    "github-token",
    "gitlab-token",
    "npm-token",
    "sendgrid-token",
    "slack-token",
    "aws-access-key",
    "private-key",
    "jwt",
    "anthropic-token",
    "openai-token",
    "shopify-token",
    "stripe-token",
    "generic-token",
    "vault-token",
    "pypi-token",
    "huggingface-token",
    "docker-token",
    "cloudflare-token",
    "digitalocean-token",
    "linear-token",
    "supabase-token",
    "vercel-token",
    "bearer-token",
    "connection-string",
    "otpauth-uri",
    "confluent-cloud-api-secret",
    "confluent-cloud-api-secret-legacy",
    "aws-bedrock-long-term-api-key",
    "aws-bedrock-short-term-api-key",
    "elevenlabs-api-key",
    "together-ai-api-key",
    "tavily-api-key",
    "mistral-api-key",
    "cohere-api-key",
    "ai21-api-key",
    "deepgram-api-key",
    "doppler-token",
    "trigger-dev-token",
    "e2b-api-key",
    "posthog-token",
    "helicone-api-key",
    "firecrawl-api-key",
    "composio-api-key",
    "convex-deployment-key",
    "onepassword-service-account-token",
    "inngest-signing-key",
    "resend-api-key",
    "apify-api-token",
    "wandb-api-key",
    "daytona-api-key",
    "clickhouse-cloud-api-secret",
    "nvidia-api-key",
    "browserbase-api-key",
    "runpod-api-key",
    "cerebras-api-key",
    "bitwarden-secrets-manager-access-token",
    "polar-token",
    "sonarqube-token",
    "rubygems-api-key",
    "clojars-deploy-token",
    "crates-io-token",
    "dynatrace-token",
    "paddle-api-key",
    "honeycomb-api-key",
    "axiom-token",
    "aws-secret-access-key",
    "google-oauth-client-secret",
];

/// Legacy `gitleaks` table (`families.mjs:34-79`).
const GITLEAKS: &[(&str, &str)] = &[
    ("github-pat", "github-token"),
    ("github-oauth", "github-token"),
    ("github-app-token", "github-token"),
    ("github-refresh-token", "github-token"),
    ("gitlab-pat", "gitlab-token"),
    ("npm-access-token", "npm-token"),
    ("sendgrid-api-token", "sendgrid-token"),
    ("slack-bot-token", "slack-token"),
    ("aws-access-token", "aws-access-key"),
    ("private-key", "private-key"),
    ("jwt", "jwt"),
    ("anthropic-api-key", "anthropic-token"),
    ("openai-api-key", "openai-token"),
    ("shopify-access-token", "shopify-token"),
    ("stripe-access-token", "stripe-token"),
    ("generic-api-key", "generic-token"),
    ("perplexity-api-key", "perplexity-api-key"),
    (
        "gitlab-runner-authentication-token",
        "gitlab-runner-authentication-token",
    ),
    (
        "gitlab-runner-authentication-token-routable",
        "gitlab-runner-authentication-token",
    ),
    ("travisci-access-token", "travisci-api-token"),
    ("mailgun-signing-key", "mailgun-api-key-triplet"),
    (
        "aws-amazon-bedrock-api-key-long-lived",
        "aws-bedrock-long-term-api-key",
    ),
    (
        "aws-amazon-bedrock-api-key-short-lived",
        "aws-bedrock-short-term-api-key",
    ),
    ("cohere-api-token", "cohere-api-key"),
    ("doppler-api-token", "doppler-personal-token"),
    (
        "clickhouse-cloud-api-secret-key",
        "clickhouse-cloud-api-secret",
    ),
    ("rubygems-api-token", "rubygems-api-key"),
    ("clojars-api-token", "clojars-deploy-token"),
    ("dynatrace-api-token", "dynatrace-token"),
    ("sonar-api-token", "sonarqube-token"),
    (
        "1password-service-account-token",
        "onepassword-service-account-token",
    ),
];

/// Legacy `trufflehog` table (`families.mjs:80-124`).
const TRUFFLEHOG: &[(&str, &str)] = &[
    ("Github", "github-token"),
    ("Gitlab", "gitlab-token"),
    ("Npm", "npm-token"),
    ("SendGrid", "sendgrid-token"),
    ("Slack", "slack-token"),
    ("AWS", "aws-access-key"),
    ("PrivateKey", "private-key"),
    ("JWT", "jwt"),
    ("Anthropic", "anthropic-token"),
    ("OpenAI", "openai-token"),
    ("Shopify", "shopify-token"),
    ("Stripe", "stripe-token"),
    ("Replicate", "replicate-api-token"),
    ("Groq", "groq-api-key"),
    ("XAI", "xai-api-key"),
    ("OpenRouter", "openrouter-api-key"),
    ("LangSmith", "langsmith-api-key"),
    ("Langfuse", "langfuse-secret-key"),
    ("Pinecone", "pinecone-api-key"),
    ("TravisCI", "travisci-api-token"),
    ("ElevenLabs", "elevenlabs-api-key"),
    ("Deepgram", "deepgram-api-key"),
    ("Doppler", "doppler-token"),
    ("PosthogApp", "posthog-token"),
    ("NVAPI", "nvidia-api-key"),
    ("RubyGems", "rubygems-api-key"),
    ("Apify", "apify-api-token"),
    ("WeightsAndBiases", "wandb-api-key"),
    ("OpenAIAdmin", "openai-admin-api-key"),
];

/// Legacy `flareRedact` table (`families.mjs:145-163`).
const FLARE_REDACT: &[(&str, &str)] = &[
    ("github_token", "github-token"),
    ("gitlab_token", "gitlab-token"),
    ("npm_token", "npm-token"),
    ("sendgrid_key", "sendgrid-token"),
    ("slack_token", "slack-token"),
    ("aws_access_key", "aws-access-key"),
    ("aws_secret_key", "aws-access-key"),
    ("private_key", "private-key"),
    ("jwt", "jwt"),
    ("anthropic_key", "anthropic-token"),
    ("openai_key", "openai-token"),
    ("shopify_token", "shopify-token"),
    ("stripe_key", "stripe-token"),
    ("generic_assignment", "generic-token"),
    ("vault_token", "vault-token"),
    ("huggingface_token", "huggingface-token"),
    ("digitalocean_token", "digitalocean-token"),
    ("linear_key", "linear-token"),
    ("supabase_key", "supabase-token"),
    ("bearer_token", "bearer-token"),
    ("url_credentials", "connection-string"),
    ("databricks_token", "databricks-personal-access-token"),
    ("postman_key", "postman-api-key"),
    ("netlify_token", "netlify-token"),
    ("mailgun_key", "mailgun-api-key"),
    ("groq_key", "groq-api-key"),
    ("xai_key", "xai-api-key"),
    ("openrouter_key", "openrouter-api-key"),
    ("replicate_token", "replicate-api-token"),
    ("perplexity_key", "perplexity-api-key"),
];

/// Legacy `openRedaction` table (`families.mjs:236-243`).
const OPEN_REDACTION: &[(&str, &str)] = &[
    ("GITHUB_TOKEN", "github-token"),
    ("SLACK_TOKEN", "slack-token"),
    ("NPM_TOKEN", "npm-token"),
    ("PYPI_TOKEN", "pypi-token"),
    ("SENDGRID_API_KEY", "sendgrid-token"),
    ("OPENAI_API_KEY", "openai-token"),
    ("STRIPE_API_KEY", "stripe-token"),
    ("AWS_ACCESS_KEY", "aws-access-key"),
    ("AWS_SECRET_KEY", "aws-secret-access-key"),
    ("PRIVATE_KEY", "private-key"),
    ("SSH_PRIVATE_KEY", "private-key"),
    ("JWT_TOKEN", "jwt"),
    ("BEARER_TOKEN", "bearer-token"),
    ("URL_WITH_AUTH", "connection-string"),
    ("DATABASE_CONNECTION", "connection-string"),
    ("MAILGUN_API_KEY", "mailgun-api-key"),
    ("GENERIC_SECRET", "generic-token"),
    ("GENERIC_API_KEY", "generic-token"),
];

/// Legacy `arrivalFindingTypes` (`families.mjs:183-221`): Redact Secret
/// `(detector id, finding type)` pairs labelled with an arrival family.
const ARRIVAL_FINDING_TYPES: &[(&str, &str, &str)] = &[
    (
        "github-token",
        "github_fine_grained_personal_access_token",
        "github-fine-grained-pat",
    ),
    (
        "stripe-token",
        "stripe_webhook_signing_secret",
        "stripe-webhook-signing-secret",
    ),
    (
        "slack-token",
        "slack_app_level_token",
        "slack-app-level-token",
    ),
    ("slack-token", "slack_user_token", "slack-user-token"),
    (
        "anthropic-token",
        "anthropic_enterprise_api_key",
        "anthropic-api01-key",
    ),
    (
        "anthropic-token",
        "anthropic_admin_api_key",
        "anthropic-admin01-key",
    ),
    (
        "openai-token",
        "openai_admin_api_key",
        "openai-admin-api-key",
    ),
    (
        "doppler-token",
        "doppler_personal_token",
        "doppler-personal-token",
    ),
    ("doppler-token", "doppler_cli_token", "doppler-cli-token"),
    (
        "doppler-token",
        "doppler_service_account_token",
        "doppler-service-account-token",
    ),
    (
        "doppler-token",
        "doppler_service_account_identity_token",
        "doppler-service-account-identity-token",
    ),
    ("doppler-token", "doppler_scim_token", "doppler-scim-token"),
    (
        "doppler-token",
        "doppler_audit_token",
        "doppler-audit-token",
    ),
    (
        "trigger-dev-token",
        "trigger_dev_personal_access_token",
        "trigger-dev-personal-access-token",
    ),
    (
        "posthog-token",
        "posthog_project_secret_api_key",
        "posthog-project-secret-api-key",
    ),
    (
        "helicone-api-key",
        "helicone_write_api_key",
        "helicone-write-api-key",
    ),
    (
        "composio-api-key",
        "composio_org_api_key",
        "composio-org-api-key",
    ),
    (
        "composio-api-key",
        "composio_user_api_key",
        "composio-user-api-key",
    ),
    (
        "polar-token",
        "polar_api_credential",
        "polar-api-credential",
    ),
    (
        "sonarqube-token",
        "sonarqube_analysis_token",
        "sonarqube-analysis-token",
    ),
    (
        "crates-io-token",
        "crates_io_trusted_publishing_token",
        "crates-io-trusted-publishing-token",
    ),
    (
        "axiom-token",
        "axiom_personal_token",
        "axiom-personal-token",
    ),
    (
        "vercel-token",
        "vercel_personal_access_token",
        "vercel-personal-access-token",
    ),
    (
        "vercel-token",
        "vercel_app_access_token",
        "vercel-app-access-token",
    ),
    (
        "vercel-token",
        "vercel_app_refresh_token",
        "vercel-app-refresh-token",
    ),
];

fn lookup(table: &[(&str, &'static str)], label: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(native, _)| *native == label)
        .map(|(_, family)| *family)
}

/// The family of one finding (legacy `findingFamily`, `families.mjs:250-260`).
///
/// `label` is the scanner's native rule label; `finding_type` is read only for
/// [`LabelTable::RedactSecret`]. An unmapped label yields `None`.
pub fn finding_family(
    table: LabelTable,
    label: Option<&str>,
    finding_type: Option<&str>,
) -> Option<String> {
    let label = label?;
    let family = match table {
        LabelTable::RedactSecret => {
            let arrival = finding_type.and_then(|kind| {
                ARRIVAL_FINDING_TYPES
                    .iter()
                    .find(|(detector, t, _)| *detector == label && *t == kind)
                    .map(|(_, _, family)| *family)
            });
            arrival.or_else(|| DETECTOR_FAMILIES.iter().copied().find(|f| *f == label))
        }
        LabelTable::Gitleaks => lookup(GITLEAKS, label),
        LabelTable::Trufflehog => lookup(TRUFFLEHOG, label),
        LabelTable::FlareRedact => lookup(FLARE_REDACT, label),
        LabelTable::OpenRedaction => lookup(OPEN_REDACTION, label),
    };
    family.map(str::to_owned)
}

/// The native types of `table` that map to a family, sorted. Used to build the
/// explicit allowlist of a diagnostic profile, so the allowlist cannot drift
/// from the mapping.
pub fn mapped_types(table: LabelTable) -> Vec<&'static str> {
    let entries: &[(&str, &str)] = match table {
        LabelTable::OpenRedaction => OPEN_REDACTION,
        _ => &[],
    };
    let mut types: Vec<&'static str> = entries.iter().map(|(label, _)| *label).collect();
    types.sort_unstable();
    types
}

/// The native labels of `table` that have been reviewed against the exact
/// published package, or `None` when the table has no reviewed set. Only a
/// reviewed label is ever recorded (ADR 0011).
fn reviewed_labels(table: LabelTable) -> Option<&'static [&'static str]> {
    match table {
        LabelTable::OpenRedaction => Some(OPEN_REDACTION_1_1_5_TYPES),
        _ => None,
    }
}

/// The native labels to record for a finding the scanner reported as `label`.
///
/// * a table with no reviewed set, or an absent label: none (the adapter does
///   not guess; readers see "native label unavailable");
/// * a label in the reviewed set: that label;
/// * any other string: the single [`UNRECOGNIZED_NATIVE_LABEL`] marker. The
///   reported string, which a scanner may derive from input, is dropped.
pub fn finding_native_labels(table: LabelTable, label: Option<&str>) -> Vec<NativeLabel> {
    let (Some(reviewed), Some(label)) = (reviewed_labels(table), label) else {
        return Vec::new();
    };
    let known = reviewed.binary_search(&label).is_ok();
    let recorded = if known {
        NativeLabel::new(label)
    } else {
        NativeLabel::new(UNRECOGNIZED_NATIVE_LABEL)
    };
    recorded.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_openredaction_labels_are_sorted_and_cover_the_mapping() {
        let set = OPEN_REDACTION_1_1_5_TYPES;
        assert!(set.windows(2).all(|w| w[0] < w[1]));
        for (label, _) in OPEN_REDACTION {
            assert!(set.binary_search(label).is_ok(), "{label}");
        }
        for label in set {
            assert!(NativeLabel::new(*label).is_ok(), "{label}");
        }
    }

    #[test]
    fn native_labels_are_recorded_only_from_reviewed_sets() {
        let labels = |table, label| {
            finding_native_labels(table, label)
                .iter()
                .map(|l| l.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        let or = LabelTable::OpenRedaction;
        // known and mapped, known and unmapped
        assert_eq!(labels(or, Some("AWS_SECRET_KEY")), ["AWS_SECRET_KEY"]);
        assert_eq!(labels(or, Some("EMAIL")), ["EMAIL"]);
        // absent: nothing, never a guess
        assert!(labels(or, None).is_empty());
        // unknown, oversized, unsafe: one marker, the string is dropped
        let long = "X".repeat(500);
        for odd in ["NOT_A_TYPE", "a b\nc", "é", "", long.as_str()] {
            assert_eq!(
                labels(or, Some(odd)),
                [UNRECOGNIZED_NATIVE_LABEL],
                "{odd:?}"
            );
        }
        // tables without a reviewed set record nothing
        for table in [
            LabelTable::Gitleaks,
            LabelTable::Trufflehog,
            LabelTable::FlareRedact,
            LabelTable::RedactSecret,
        ] {
            assert!(labels(table, Some("github-pat")).is_empty());
        }
    }

    #[test]
    fn native_tables() {
        let f = |t, l| finding_family(t, Some(l), None);
        assert_eq!(
            f(LabelTable::Gitleaks, "github-pat").as_deref(),
            Some("github-token")
        );
        assert_eq!(f(LabelTable::Gitleaks, "gitlab-rrt"), None);
        assert_eq!(
            f(LabelTable::Trufflehog, "AWS").as_deref(),
            Some("aws-access-key")
        );
        assert_eq!(f(LabelTable::Trufflehog, "aws"), None);
        assert_eq!(
            f(LabelTable::FlareRedact, "aws_secret_key").as_deref(),
            Some("aws-access-key")
        );
        assert_eq!(
            f(LabelTable::OpenRedaction, "AWS_SECRET_KEY").as_deref(),
            Some("aws-secret-access-key")
        );
        assert_eq!(f(LabelTable::OpenRedaction, "EMAIL"), None);
        assert_eq!(finding_family(LabelTable::Gitleaks, None, None), None);
    }

    #[test]
    fn redact_secret_arrival_types() {
        let f = |l, t| finding_family(LabelTable::RedactSecret, Some(l), t);
        assert_eq!(
            f(
                "github-token",
                Some("github_fine_grained_personal_access_token")
            )
            .as_deref(),
            Some("github-fine-grained-pat")
        );
        assert_eq!(
            f("github-token", Some("github_token")).as_deref(),
            Some("github-token")
        );
        assert_eq!(f("github-token", None).as_deref(), Some("github-token"));
        // A detector id outside the family list stays unmapped.
        assert_eq!(f("perplexity-api-key", None), None);
        // Finding types are looked up only under their own detector.
        assert_eq!(
            f("gitlab-token", Some("slack_user_token")).as_deref(),
            Some("gitlab-token")
        );
    }
}
