//! Detect browsers installed on this machine and locate the files that
//! infostealers target: the cookie, saved-password and encryption-key stores.
//!
//! Only browsers whose on-disk profile actually exists are reported — those are
//! the ones that have secrets worth protecting.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    /// Chromium-based (Chrome, Edge, Brave, Opera, Vivaldi…): SQLite cookie/
    /// Login Data stores plus a `Local State` holding the encryption key.
    Chromium,
    /// Gecko-based (Firefox): cookies.sqlite / logins.json / key4.db per profile.
    Gecko,
}

/// A browser found installed on this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installed {
    /// Display name, e.g. "Google Chrome".
    pub name: String,
    pub family: Family,
    /// Process-name stems used to recognise this browser's own processes
    /// (lowercase, no extension), e.g. ["chrome"].
    pub process_stems: Vec<String>,
    /// The sensitive files a stealer would read. Only existing paths are kept.
    pub secret_files: Vec<PathBuf>,
}

impl Installed {
    pub fn has_secrets(&self) -> bool {
        !self.secret_files.is_empty()
    }
}

struct Candidate {
    name: &'static str,
    family: Family,
    stems: &'static [&'static str],
    /// Profile/user-data directory, relative to a base dir chosen per platform.
    chromium_user_data: Option<PathBuf>,
    gecko_profiles_dir: Option<PathBuf>,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(windows)]
fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

/// Build the platform candidate list.
fn candidates() -> Vec<Candidate> {
    let mut v = Vec::new();

    #[cfg(windows)]
    {
        let local = env_dir("LOCALAPPDATA");
        let roaming = env_dir("APPDATA");
        let chromium = |sub: &str| local.as_ref().map(|b| b.join(sub));
        v.push(Candidate { name: "Google Chrome", family: Family::Chromium, stems: &["chrome"], chromium_user_data: chromium(r"Google\Chrome\User Data"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Microsoft Edge", family: Family::Chromium, stems: &["msedge", "edge"], chromium_user_data: chromium(r"Microsoft\Edge\User Data"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Brave", family: Family::Chromium, stems: &["brave"], chromium_user_data: chromium(r"BraveSoftware\Brave-Browser\User Data"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Vivaldi", family: Family::Chromium, stems: &["vivaldi"], chromium_user_data: chromium(r"Vivaldi\User Data"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Opera", family: Family::Chromium, stems: &["opera"], chromium_user_data: roaming.as_ref().map(|b| b.join(r"Opera Software\Opera Stable")), gecko_profiles_dir: None });
        v.push(Candidate { name: "Opera GX", family: Family::Chromium, stems: &["opera", "opera_gx"], chromium_user_data: roaming.as_ref().map(|b| b.join(r"Opera Software\Opera GX Stable")), gecko_profiles_dir: None });
        v.push(Candidate { name: "Mozilla Firefox", family: Family::Gecko, stems: &["firefox"], chromium_user_data: None, gecko_profiles_dir: roaming.as_ref().map(|b| b.join(r"Mozilla\Firefox\Profiles")) });
    }

    #[cfg(target_os = "macos")]
    {
        let as_ = home().map(|h| h.join("Library/Application Support"));
        let cu = |sub: &str| as_.as_ref().map(|b| b.join(sub));
        v.push(Candidate { name: "Google Chrome", family: Family::Chromium, stems: &["google chrome", "chrome"], chromium_user_data: cu("Google/Chrome"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Microsoft Edge", family: Family::Chromium, stems: &["microsoft edge", "edge"], chromium_user_data: cu("Microsoft Edge"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Brave", family: Family::Chromium, stems: &["brave browser", "brave"], chromium_user_data: cu("BraveSoftware/Brave-Browser"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Vivaldi", family: Family::Chromium, stems: &["vivaldi"], chromium_user_data: cu("Vivaldi"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Opera", family: Family::Chromium, stems: &["opera"], chromium_user_data: cu("com.operasoftware.Opera"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Mozilla Firefox", family: Family::Gecko, stems: &["firefox"], chromium_user_data: None, gecko_profiles_dir: cu("Firefox/Profiles") });
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let cfg = home().map(|h| h.join(".config"));
        let cu = |sub: &str| cfg.as_ref().map(|b| b.join(sub));
        v.push(Candidate { name: "Google Chrome", family: Family::Chromium, stems: &["chrome"], chromium_user_data: cu("google-chrome"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Chromium", family: Family::Chromium, stems: &["chromium"], chromium_user_data: cu("chromium"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Brave", family: Family::Chromium, stems: &["brave"], chromium_user_data: cu("BraveSoftware/Brave-Browser"), gecko_profiles_dir: None });
        v.push(Candidate { name: "Mozilla Firefox", family: Family::Gecko, stems: &["firefox"], chromium_user_data: None, gecko_profiles_dir: home().map(|h| h.join(".mozilla/firefox")) });
    }

    v
}

/// Chromium secret files within a user-data dir's default profile.
fn chromium_secret_files(user_data: &Path) -> Vec<PathBuf> {
    let p = user_data.join("Default");
    let mut files = vec![
        user_data.join("Local State"), // AES key (DPAPI/Keychain wrapped)
        p.join("Network/Cookies"),     // newer Chromium
        p.join("Cookies"),             // older Chromium
        p.join("Login Data"),          // saved passwords
        p.join("Web Data"),            // autofill, cards
    ];
    files.retain(|f| f.exists());
    files
}

/// Gecko secret files across all profiles under the profiles dir.
fn gecko_secret_files(profiles: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles) {
        for entry in rd.flatten() {
            let prof = entry.path();
            if !prof.is_dir() {
                continue;
            }
            for name in ["cookies.sqlite", "logins.json", "key4.db"] {
                let f = prof.join(name);
                if f.exists() {
                    files.push(f);
                }
            }
        }
    }
    files
}

/// Detect installed browsers that have an on-disk profile with secrets.
pub fn detect_installed() -> Vec<Installed> {
    let mut out = Vec::new();
    for c in candidates() {
        let secret_files = match c.family {
            Family::Chromium => c.chromium_user_data.as_deref().map(chromium_secret_files).unwrap_or_default(),
            Family::Gecko => c.gecko_profiles_dir.as_deref().map(gecko_secret_files).unwrap_or_default(),
        };
        if secret_files.is_empty() {
            continue; // not installed, or no profile/secrets yet
        }
        out.push(Installed {
            name: c.name.to_string(),
            family: c.family,
            process_stems: c.stems.iter().map(|s| s.to_string()).collect(),
            secret_files,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_runs_without_panic() {
        // On a dev box this may be empty or not; just assert structural validity.
        for b in detect_installed() {
            assert!(!b.name.is_empty());
            assert!(!b.process_stems.is_empty());
            assert!(b.has_secrets());
        }
    }

    #[test]
    fn chromium_files_filtered_to_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ud = dir.path().to_path_buf();
        std::fs::create_dir_all(ud.join("Default/Network")).unwrap();
        std::fs::write(ud.join("Local State"), b"{}").unwrap();
        std::fs::write(ud.join("Default/Network/Cookies"), b"x").unwrap();
        std::fs::write(ud.join("Default/Login Data"), b"x").unwrap();

        let files = chromium_secret_files(&ud);
        assert!(files.iter().any(|f| f.ends_with("Local State")));
        assert!(files.iter().any(|f| f.ends_with("Cookies")));
        assert!(files.iter().any(|f| f.ends_with("Login Data")));
        // "Web Data" was never created, so it must be absent.
        assert!(!files.iter().any(|f| f.ends_with("Web Data")));
    }
}
