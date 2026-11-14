//! Authoritative scan-profile registry.
//!
//! Single source of truth for which scan profiles exist, which ones users may
//! create, which may serve as the system-wide default, and how retired
//! compatibility values are normalized at API boundaries. Plan shapes stay in
//! [`super::creation::build_scan_plan`]; the database CHECK constraint keeps
//! every historical value readable.
//!
//! Canonical, user-facing set:
//! - IP/CIDR tasks: `port_only`, `service_inventory`, `vulnerability_scan`
//! - Domain tasks: `dns_records` parent + server-generated IP follow-up children
//! - UDP tasks: `udp_inventory`
//!
//! Retired values (accepted at boundaries, normalized before persistence):
//! - `legacy` -> `port_only` (best-effort service detection is no longer a mode)
//! - `dns_ports` / `dns_full` -> `dns_records` parent + `port_only` follow-up
//! - `udp_passive` -> rejected outright (passive engine removed)

/// IP/CIDR execution profiles. `legacy` stays listed so historical tasks keep
/// validating in display and dispatch code, but it is not defaultable and new
/// tasks are normalized away from it via [`ip_profile_alias`].
pub const IP_PROFILES: [&str; 4] = [
    "legacy",
    "port_only",
    "service_inventory",
    "vulnerability_scan",
];

/// Profiles an operator may select as the system-wide default for new tasks.
pub const DEFAULTABLE_IP_PROFILES: [&str; 3] =
    ["port_only", "service_inventory", "vulnerability_scan"];

/// The only DNS parent profile; retired `dns_ports`/`dns_full` map onto it.
pub const DNS_PARENT_PROFILE: &str = "dns_records";

/// Active UDP profile. The retired `udp_passive` mode was removed entirely.
pub const UDP_PROFILES: [&str; 1] = ["udp_inventory"];

/// Fallback used when no valid default profile is configured.
pub const FALLBACK_DEFAULT_PROFILE: &str = "port_only";

/// Profiles valid for IP/CIDR tasks and historical default settings. DNS
/// profiles require the dedicated domain-task endpoint and must never be
/// inherited by an IP task.
pub fn is_ip_scan_profile(profile: &str) -> bool {
    IP_PROFILES.contains(&profile)
}

/// Profiles selectable as the system-wide default for new tasks.
pub fn is_defaultable_profile(profile: &str) -> bool {
    DEFAULTABLE_IP_PROFILES.contains(&profile)
}

/// Canonical replacement for a retired IP-side profile, if any.
pub fn ip_profile_alias(profile: &str) -> Option<&'static str> {
    match profile {
        "legacy" => Some("port_only"),
        _ => None,
    }
}

/// Canonical replacement for a retired in-scanner DNS profile: the unified
/// `dns_records` parent task plus a `port_only` IP follow-up child.
pub fn dns_profile_alias(profile: &str) -> Option<(&'static str, &'static str)> {
    match profile {
        "dns_ports" | "dns_full" => Some((DNS_PARENT_PROFILE, "port_only")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sets_are_disjoint_from_retired_values() {
        for profile in DEFAULTABLE_IP_PROFILES {
            assert!(is_ip_scan_profile(profile));
            assert!(ip_profile_alias(profile).is_none());
        }
        assert!(is_ip_scan_profile("legacy"));
        assert!(!is_defaultable_profile("legacy"));
        assert_eq!(ip_profile_alias("legacy"), Some("port_only"));
        assert!(!is_defaultable_profile("udp_inventory"));
        assert!(is_defaultable_profile(FALLBACK_DEFAULT_PROFILE));
    }

    #[test]
    fn retired_dns_profiles_map_to_unified_parent_and_follow_up() {
        for profile in ["dns_ports", "dns_full"] {
            assert_eq!(
                dns_profile_alias(profile),
                Some((DNS_PARENT_PROFILE, "port_only"))
            );
        }
        assert_eq!(dns_profile_alias(DNS_PARENT_PROFILE), None);
        assert_eq!(dns_profile_alias("port_only"), None);
    }
}
