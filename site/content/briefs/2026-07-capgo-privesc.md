---
title: Capgo Privilege Escalation via Retained Super_Admin Privileges (CVE-2026-56241)
slug: 2026-07-capgo-privesc
description: A privilege escalation vulnerability, CVE-2026-56241, in Capgo versions prior to 12.128.2 allows demoted super_admin users to retain access to critical RPCs, enabling them to indefinitely enumerate and bulk delete non-compliant bundles across an organization.
date: "2026-07-12T12:22:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - capgo
  - cloud
vendors:
  - Capgo
products:
  - Capgo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Capgo before 12.128.2 contains a privilege escalation vulnerability where demoted super_admin users retain access to delete_non_compliant_bundles and count_non_compliant_bundles RPCs due to stale org_users.user_right column not being cleared during role binding deletion.
    confidence_band: high
cves:
  - id: CVE-2026-56241
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56241
---

A critical privilege escalation vulnerability, tracked as CVE-2026-56241, has been identified in Capgo versions released before 12.128.2. This flaw allows a previously appointed super_admin user, even after being demoted from that role, to retain unauthorized access to specific Remote Procedure Calls (RPCs): `delete_non_compliant_bundles` and `count_non_compliant_bundles`. The root cause is an issue where the `org_users.user_right` column is not properly cleared when role bindings are removed. An attacker can exploit this oversight to continue performing high-privilege actions, such as enumerating and bulk deleting non-compliant bundles across an entire organization, effectively maintaining super_admin capabilities indefinitely despite their demoted status. This vulnerability poses a significant risk to data integrity and service availability for organizations utilizing Capgo.

## Attack Chain

1. An adversary, previously a `super_admin` user within a Capgo organization, is officially demoted from their administrative role.
2. Due to the vulnerability (CVE-2026-56241), the `org_users.user_right` column associated with the demoted user's account is not properly cleared.
3. The demoted user exploits this oversight by continuing to invoke the `delete_non_compliant_bundles` and `count_non_compliant_bundles` RPCs.
4. The Capgo application, processing these RPCs, grants access based on the stale `super_admin` privileges.
5. The adversary successfully enumerates all non-compliant bundles within the organization.
6. The adversary proceeds to bulk delete these non-compliant bundles across the entire organization.
7. The objective is achieved, leading to unauthorized data manipulation and potential service disruption.

## Impact

Successful exploitation of CVE-2026-56241 grants a demoted super_admin user the ability to perform indefinite and unauthorized enumeration and bulk deletion of non-compliant bundles across the entire Capgo organization. This can lead to severe data integrity issues, potential data loss, and significant service disruption by removing essential data assets. The CVSS v3.1 Base Score of 8.3 indicates a high severity risk, reflecting the critical impact on confidentiality, integrity, and availability. Organizations using affected Capgo versions face a substantial risk of malicious or accidental deletion of critical data by privileged insiders who should no longer possess such capabilities.

## Recommendation

* Patch CVE-2026-56241 immediately by upgrading Capgo to version 12.128.2 or later to ensure `org_users.user_right` columns are properly cleared upon role demotion.
* Review Capgo application logs for unexpected `delete_non_compliant_bundles` or `count_non_compliant_bundles` RPC calls originating from demoted user accounts.
* Implement robust auditing and alerting for critical administrative actions within Capgo, paying particular attention to bundle management operations by all users, especially recently demoted ones.
