//! Vulnerability-category registry and candidate model ported from
//! `legacy-python/gloscope/models.py`. The category table is the single
//! source of truth: CWE lookup and `check_id` fragment inference both derive
//! from it.

use serde::Serialize;

/// One vulnerability category: its CWE id and the `check_id` substring
/// fragments used to infer it from a semgrep rule id.
struct VulnCategory {
    name: &'static str,
    cwe: &'static str,
    fragments: &'static [&'static str],
}

const VULN_CATEGORIES: &[VulnCategory] = &[
    VulnCategory {
        name: "sql_injection",
        cwe: "CWE-89",
        fragments: &[
            "sql-injection",
            "sqli",
            "insecure-sql-query",
            "tainted-sql-string",
        ],
    },
    VulnCategory {
        name: "ssrf",
        cwe: "CWE-918",
        fragments: &["ssrf", "request-forgery"],
    },
    VulnCategory {
        name: "path_traversal",
        cwe: "CWE-22",
        fragments: &["path-traversal", "traversal"],
    },
    VulnCategory {
        name: "command_injection",
        cwe: "CWE-78",
        fragments: &[
            "command-injection",
            "os-command-injection",
            "subprocess-injection",
            "subprocess-shell-true",
            "dangerous-subprocess-use",
        ],
    },
    VulnCategory {
        name: "xss",
        cwe: "CWE-79",
        fragments: &["xss", "cross-site-scripting"],
    },
    VulnCategory {
        name: "ssti",
        cwe: "CWE-1336",
        fragments: &["ssti", "server-side-template-injection"],
    },
    VulnCategory {
        name: "code_injection",
        cwe: "CWE-94",
        fragments: &["user-eval", "eval-detected"],
    },
    VulnCategory {
        name: "deserialization",
        cwe: "CWE-502",
        fragments: &["pickle", "deserialization", "insecure-deserialization"],
    },
    VulnCategory {
        name: "regex_dos",
        cwe: "CWE-1333",
        fragments: &["regex-dos", "non-literal-regexp", "redos"],
    },
    VulnCategory {
        name: "improper_check",
        cwe: "CWE-706",
        fragments: &["non-literal-import"],
    },
];

/// Looks up the category name owning a given CWE id, if any.
pub(crate) fn category_for_cwe(cwe: &str) -> Option<&'static str> {
    VULN_CATEGORIES
        .iter()
        .find(|category| category.cwe == cwe)
        .map(|category| category.name)
}

/// Normalizes semgrep metadata's `cwe` field, which varies in shape
/// (`"CWE-89: ..."`, `["CWE-89"]`, `"89"`) into a canonical `"CWE-NN"`.
pub(crate) fn normalize_cwe(raw: Option<&serde_json::Value>) -> Option<String> {
    let raw = raw?;
    let raw = match raw {
        serde_json::Value::Array(items) => items.first()?,
        other => other,
    };
    let raw = raw.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    let token = raw.split(':').next().unwrap_or("").trim().to_uppercase();
    let digits = token.strip_prefix("CWE-").unwrap_or(token.as_str());
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        Some(format!("CWE-{digits}"))
    } else {
        None
    }
}

/// Infers a CWE id from a semgrep `check_id` by matching known fragments.
pub(crate) fn infer_cwe(check_id: &str) -> Option<&'static str> {
    let low = check_id.to_lowercase();
    VULN_CATEGORIES
        .iter()
        .find(|category| category.fragments.iter().any(|fragment| low.contains(fragment)))
        .map(|category| category.cwe)
}

/// Infers a category name from a `check_id`, preferring an already-resolved
/// CWE id when it maps to a known category.
pub(crate) fn infer_category(check_id: &str, cwe: Option<&str>) -> &'static str {
    if let Some(cwe) = cwe
        && let Some(category) = category_for_cwe(cwe)
    {
        return category;
    }
    let low = check_id.to_lowercase();
    VULN_CATEGORIES
        .iter()
        .find(|category| category.fragments.iter().any(|fragment| low.contains(fragment)))
        .map(|category| category.name)
        .unwrap_or("unknown")
}

/// A candidate vulnerability location produced by the semgrep layer: may or
/// may not be a real vulnerability, pending downstream triage/verification.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub check_id: String,
    /// Relative to the target repo root.
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet: String,
    pub message: String,
    pub cwe: Option<String>,
    pub category: String,
    pub source: &'static str,
}

impl Candidate {
    /// Not yet consumed until `submit_verdict`/report tools land (M4/M6).
    #[allow(dead_code)]
    pub fn location(&self) -> String {
        format!("{}:{}", self.path, self.start_line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn normalizes_cwe_shapes() {
        assert_eq!(normalize_cwe(Some(&json!("CWE-89: SQL Injection"))), Some("CWE-89".to_string()));
        assert_eq!(normalize_cwe(Some(&json!(["CWE-89"]))), Some("CWE-89".to_string()));
        assert_eq!(normalize_cwe(Some(&json!("89"))), Some("CWE-89".to_string()));
        assert_eq!(normalize_cwe(Some(&json!(""))), None);
        assert_eq!(normalize_cwe(Some(&json!([]))), None);
        assert_eq!(normalize_cwe(None), None);
    }

    #[test]
    fn infers_cwe_from_check_id_fragments() {
        assert_eq!(
            infer_cwe("python.django.security.injection.sql.sqli"),
            Some("CWE-89")
        );
        assert_eq!(infer_cwe("some-unrelated-rule"), None);
    }

    #[test]
    fn infers_category_prefers_known_cwe_then_fragments() {
        assert_eq!(infer_category("whatever", Some("CWE-79")), "xss");
        assert_eq!(infer_category("whatever", Some("CWE-704")), "unknown");
        assert_eq!(infer_category("tainted-sql-string-rule", None), "sql_injection");
        assert_eq!(infer_category("no-match-rule", None), "unknown");
    }
}
