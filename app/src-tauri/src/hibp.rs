//! Have I Been Pwned "Pwned Passwords" check with k-anonymity: only the first 5 hex characters
//! of each password's SHA-1 leave the machine; the matching suffixes come back and are compared
//! here. `Add-Padding` makes every response look the same size.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};

use crate::vault::{io, VResult, VaultError};

const API: &str = "https://api.pwnedpasswords.com/range/";

/// SHA-1 as upper-case hex, split into the 5-character prefix that is sent and the rest.
fn split(password: &str) -> (String, String) {
    let hex: String = Sha1::digest(password.as_bytes()).iter().map(|b| format!("{b:02X}")).collect();
    let (a, b) = hex.split_at(5);
    (a.to_string(), b.to_string())
}

/// `SUFFIX:COUNT` lines; 0 when the suffix is absent.
fn count_in(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

fn client() -> VResult<reqwest::Client> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(20))
        .user_agent("Passwords-app")
        .build()
        .map_err(|e| VaultError::Offline(e.to_string()))
}

/// How many times each password appears in known breaches (same order as the input).
pub async fn check(passwords: Vec<String>) -> VResult<Vec<u64>> {
    let http = client()?;
    let hashes: Vec<(String, String)> = passwords.iter().map(|p| split(p)).collect();
    let mut ranges: HashMap<&str, String> = HashMap::new();
    for (prefix, _) in &hashes {
        if ranges.contains_key(prefix.as_str()) {
            continue;
        }
        let res = http
            .get(format!("{API}{prefix}"))
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| VaultError::Offline(e.to_string()))?;
        if !res.status().is_success() {
            return Err(VaultError::Server(format!("haveibeenpwned: {}", res.status())));
        }
        ranges.insert(prefix, res.text().await.map_err(|e| VaultError::Offline(e.to_string()))?);
    }
    Ok(hashes.iter().map(|(p, s)| count_in(&ranges[p.as_str()], s)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sha1_into_prefix_and_suffix() {
        assert_eq!(split("password"), ("5BAA6".to_string(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8".to_string()));
    }

    #[test]
    fn finds_the_count_for_a_suffix_in_a_range_response() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\nFFFF0000000000000000000000000000000:0\r\n";
        assert_eq!(count_in(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 10434004);
        assert_eq!(count_in(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), 10434004, "case does not matter");
        assert_eq!(count_in(body, "ABCDEF0000000000000000000000000000A"), 0);
        assert_eq!(count_in(body, "FFFF0000000000000000000000000000000"), 0, "padding rows have count 0");
    }

    /// Live call to api.pwnedpasswords.com: `cargo test -p pwd-app hibp_live -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn hibp_live() {
        let counts = check(vec!["password".into(), "Zt4$wq-Lm8!pXv2#gN7&rK1".into()]).await.unwrap();
        assert!(counts[0] > 1_000_000, "{counts:?}");
        assert_eq!(counts[1], 0);
    }
}
