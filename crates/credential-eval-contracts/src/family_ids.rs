//! Family id namespaces and twin scoping (issue #56).
//!
//! Adapters label findings with the legacy `bench` family ids
//! (`github-token`, `connection-string`, ...). Evidence snapshots from
//! `snapshot-2026.10.01.2` carry `provider:family` ids
//! (`github:classic-personal-access-token`). Scoped twin scoring compares a
//! finding's family with the twin's, so comparing the raw strings makes every
//! mapped finding on an evidence twin "another family".
//!
//! [`same_family`] is the single comparison. Two ids are the same family when
//! they are equal, or when a legacy id covers an evidence id. A legacy id is
//! coarser than an evidence id, so it covers either a whole provider (`github:`)
//! or one exact evidence family. The table is data owned by the protocol; it
//! never reads a scanner or a corpus case and never relabels an expected family.
//! A legacy id without an entry covers nothing (fails toward co-detection, as
//! before). Changing the table is a protocol revision.

/// Version of the legacy-to-evidence coverage table.
pub const FAMILY_COVERAGE_VERSION: &str = "2";

/// `(legacy id, covered evidence families)`. An entry ending in `:` covers every
/// family of that provider; any other entry covers exactly that family.
const COVERAGE: &[(&str, &[&str])] = &[
    ("ai21-api-key", &["ai21:"]),
    ("anthropic-admin01-key", &["anthropic:admin-api-key"]),
    ("anthropic-api01-key", &["anthropic:compliance-access-key"]),
    ("anthropic-token", &["anthropic:"]),
    ("apify-api-token", &["apify:"]),
    ("aws-access-key", &["aws:"]),
    (
        "aws-bedrock-long-term-api-key",
        &["aws-bedrock:long-term-api-key"],
    ),
    (
        "aws-bedrock-short-term-api-key",
        &["aws-bedrock:short-term-api-key"],
    ),
    ("aws-secret-access-key", &["aws:iam-user-secret-access-key"]),
    ("axiom-personal-token", &["axiom:personal-token"]),
    ("axiom-token", &["axiom:"]),
    ("bearer-token", &["generic:bearer-token"]),
    ("bitwarden-secrets-manager-access-token", &["bitwarden:"]),
    ("browserbase-api-key", &["browserbase:"]),
    ("cerebras-api-key", &["cerebras:"]),
    ("clickhouse-cloud-api-secret", &["clickhouse-cloud:"]),
    ("clojars-deploy-token", &["clojars:"]),
    ("cloudflare-token", &["cloudflare:"]),
    ("cohere-api-key", &["cohere:"]),
    ("composio-api-key", &["composio:"]),
    ("composio-org-api-key", &["composio:org-api-key"]),
    ("composio-user-api-key", &["composio:user-api-key"]),
    (
        "confluent-cloud-api-secret",
        &["confluent:cloud-api-secret"],
    ),
    (
        "confluent-cloud-api-secret-legacy",
        &["confluent:cloud-api-secret-legacy"],
    ),
    ("connection-string", &["generic:connection-string-password"]),
    ("convex-deployment-key", &["convex:"]),
    ("crates-io-token", &["crates-io:"]),
    (
        "crates-io-trusted-publishing-token",
        &["crates-io:trusted-publishing-token"],
    ),
    ("databricks-personal-access-token", &["databricks:"]),
    ("daytona-api-key", &["daytona:"]),
    ("deepgram-api-key", &["deepgram:"]),
    ("digitalocean-token", &["digitalocean:"]),
    ("docker-token", &["docker:"]),
    ("doppler-audit-token", &["doppler:audit-token"]),
    ("doppler-cli-token", &["doppler:cli-token"]),
    ("doppler-personal-token", &["doppler:personal-token"]),
    ("doppler-scim-token", &["doppler:scim-token"]),
    (
        "doppler-service-account-identity-token",
        &["doppler:service-account-identity-token"],
    ),
    (
        "doppler-service-account-token",
        &["doppler:service-account-token"],
    ),
    ("doppler-token", &["doppler:"]),
    ("dynatrace-token", &["dynatrace:"]),
    ("e2b-api-key", &["e2b:"]),
    ("elevenlabs-api-key", &["elevenlabs:"]),
    ("firecrawl-api-key", &["firecrawl:"]),
    (
        "generic-token",
        &["generic:unclassified-assignment-literal"],
    ),
    (
        "github-fine-grained-pat",
        &["github:fine-grained-personal-access-token"],
    ),
    ("github-token", &["github:"]),
    (
        "gitlab-runner-authentication-token",
        &["gitlab:runner-authentication-token"],
    ),
    ("gitlab-token", &["gitlab:"]),
    (
        "google-oauth-client-secret",
        &["google:oauth-client-secret"],
    ),
    ("groq-api-key", &["groq:"]),
    ("helicone-api-key", &["helicone:api-key"]),
    ("helicone-write-api-key", &["helicone:write-api-key"]),
    ("honeycomb-api-key", &["honeycomb:"]),
    ("huggingface-token", &["huggingface:"]),
    ("inngest-signing-key", &["inngest:"]),
    ("jwt", &["generic:jwt"]),
    ("langfuse-secret-key", &["langfuse:"]),
    ("langsmith-api-key", &["langsmith:"]),
    ("linear-token", &["linear:"]),
    ("mailgun-api-key", &["mailgun:"]),
    ("mailgun-api-key-triplet", &["mailgun:"]),
    ("mistral-api-key", &["mistral:"]),
    ("netlify-token", &["netlify:"]),
    ("npm-token", &["npm:"]),
    ("nvidia-api-key", &["nvidia:"]),
    ("onepassword-service-account-token", &["onepassword:"]),
    ("openai-admin-api-key", &["openai:admin-api-key"]),
    ("openai-token", &["openai:"]),
    ("openrouter-api-key", &["openrouter:"]),
    ("otpauth-uri", &["generic:otp-seed"]),
    ("paddle-api-key", &["paddle:"]),
    ("perplexity-api-key", &["perplexity:"]),
    ("pinecone-api-key", &["pinecone:"]),
    ("polar-api-credential", &["polar:api-credential"]),
    ("polar-token", &["polar:"]),
    (
        "posthog-project-secret-api-key",
        &["posthog:project-secret-api-key"],
    ),
    ("posthog-token", &["posthog:"]),
    ("postman-api-key", &["postman:"]),
    ("private-key", &["generic:private-key"]),
    ("pypi-token", &["pypi:"]),
    ("replicate-api-token", &["replicate:"]),
    ("resend-api-key", &["resend:"]),
    ("rubygems-api-key", &["rubygems:"]),
    ("runpod-api-key", &["runpod:"]),
    ("sendgrid-token", &["sendgrid:"]),
    ("shopify-token", &["shopify:"]),
    ("slack-app-level-token", &["slack:app-level-token"]),
    ("slack-token", &["slack:"]),
    ("slack-user-token", &["slack:user-token"]),
    ("sonarqube-analysis-token", &["sonarqube:analysis-token"]),
    ("sonarqube-token", &["sonarqube:"]),
    ("stripe-token", &["stripe:"]),
    (
        "stripe-webhook-signing-secret",
        &["stripe:webhook-signing-secret"],
    ),
    ("supabase-token", &["supabase:"]),
    ("tavily-api-key", &["tavily:"]),
    ("together-ai-api-key", &["together:"]),
    ("travisci-api-token", &["travis-ci:"]),
    (
        "trigger-dev-personal-access-token",
        &["trigger-dev:personal-access-token"],
    ),
    ("trigger-dev-token", &["trigger-dev:"]),
    ("vault-token", &["hashicorp-vault:"]),
    ("vercel-app-access-token", &["vercel:app-access-token"]),
    ("vercel-app-refresh-token", &["vercel:app-refresh-token"]),
    (
        "vercel-personal-access-token",
        &["vercel:personal-access-token"],
    ),
    ("vercel-token", &["vercel:"]),
    ("wandb-api-key", &["wandb:"]),
    ("xai-api-key", &["xai:"]),
];

/// Whether the legacy id `legacy` covers the evidence id `evidence`.
pub fn legacy_covers(legacy: &str, evidence: &str) -> bool {
    COVERAGE
        .binary_search_by(|(id, _)| (*id).cmp(legacy))
        .is_ok_and(|i| {
            COVERAGE[i].1.iter().any(|entry| {
                if entry.ends_with(':') {
                    evidence.starts_with(entry)
                } else {
                    evidence == *entry
                }
            })
        })
}

/// Whether a finding's `finding` family is the same family as the twin's
/// `scope` family: equal ids, or a legacy id covering an evidence id.
pub fn same_family(finding: &str, scope: &str) -> bool {
    finding == scope || legacy_covers(finding, scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(COVERAGE.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn every_entry_is_an_evidence_shape() {
        for (legacy, entries) in COVERAGE {
            assert!(!legacy.contains(':'), "{legacy}");
            assert!(!entries.is_empty(), "{legacy}");
            for entry in *entries {
                let (provider, rest) = entry.split_once(':').expect(entry);
                assert!(!provider.is_empty(), "{entry}");
                assert!(!rest.contains(':'), "{entry}");
            }
        }
    }

    #[test]
    fn equal_ids_match_in_either_namespace() {
        assert!(same_family("github-token", "github-token"));
        assert!(same_family("github:a", "github:a"));
        assert!(!same_family("github:a", "github:b"));
    }

    #[test]
    fn legacy_ids_cover_evidence_ids() {
        assert!(same_family(
            "github-token",
            "github:classic-personal-access-token"
        ));
        assert!(same_family(
            "connection-string",
            "generic:connection-string-password"
        ));
        assert!(same_family(
            "aws-access-key",
            "aws:sts-temporary-access-key"
        ));
        // exact entries do not widen to the provider
        assert!(!same_family(
            "github-fine-grained-pat",
            "github:oauth-access-token"
        ));
        // provider prefixes do not collide on a shared leading word
        assert!(!same_family(
            "aws-access-key",
            "aws-bedrock:long-term-api-key"
        ));
        // another provider is another family
        assert!(!same_family("slack-token", "github:oauth-access-token"));
        // an id the table does not know covers nothing
        assert!(!same_family("unknown-token", "github:oauth-access-token"));
    }

    /// Each specific Anthropic legacy id is pinned to the evidence family that
    /// owns its documented prefix (contract `^sk-ant-<class>-...`), not merely
    /// to a family that exists in the snapshot (issue #63).
    #[test]
    fn anthropic_class_ids_pin_their_prefix_class() {
        // (legacy id, documented prefix, evidence family that owns the prefix)
        let classes = [
            (
                "anthropic-admin01-key",
                "sk-ant-admin01-",
                "anthropic:admin-api-key",
            ),
            (
                "anthropic-api01-key",
                "sk-ant-api01-",
                "anthropic:compliance-access-key",
            ),
        ];
        let api03 = "anthropic:secret-api-key"; // `sk-ant-api03-`
        for (legacy, prefix, family) in classes {
            assert!(same_family(legacy, family), "{legacy} ({prefix})");
            assert!(!same_family(legacy, api03), "{legacy} must not cover api03");
        }
        assert!(!same_family(
            "anthropic-api01-key",
            "anthropic:admin-api-key"
        ));
        assert!(!same_family(
            "anthropic-admin01-key",
            "anthropic:compliance-access-key"
        ));
    }

    /// ADR 0019: a provider-wide entry covers every family of its provider,
    /// including a sibling class a scoped twin wears. Pinned so a change is a
    /// reviewed revision.
    #[test]
    fn provider_wide_entry_covers_sibling_class_twin_scopes() {
        for scope in [
            "anthropic:admin-api-key",
            "anthropic:compliance-access-key",
            "anthropic:secret-api-key",
        ] {
            assert!(same_family("anthropic-token", scope), "{scope}");
        }
    }
}
