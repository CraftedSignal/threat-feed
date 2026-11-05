---
brief_id: brief-2026-11-05-keycloak-mitm
event_id: brief-2026-11-05-keycloak-mitm
revision: 1
activity_at: "2026-11-05T20:29:41Z"
title: 'Keycloak Admin CLI: Man-in-the-Middle credential theft (CVE-2026-96453)'
slug: 2026-11-keycloak-mitm
description: The Keycloak Admin CLI (kcadm) tool fails to properly validate server certificates when a custom truststore is configured, enabling attackers to intercept and compromise administrative credentials via man-in-the-middle attacks.
date: "2026-11-05T20:29:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
vendors:
  - Keycloak
products:
  - Keycloak Admin CLI (kcadm)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This allows a network attacker to impersonate the Keycloak server, steal administrative credentials, and perform unauthorized management actions.
    confidence_band: high
cves:
  - id: CVE-2026-96453
    cvss: 8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96453
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify the use of kcadm command-line tools across the environment that explicitly point to custom truststores.
      technique_id: T1552
      data_needed:
        - Endpoint process creation logs (Process Name, CommandLine)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw occurs when a custom truststore is provided to verify the server identity.
  mitigation_plan:
    - priority: immediate
      action: Cease the use of custom truststores with kcadm until a security patch is verified and applied.
      owner: IT Operations
      addresses: CVE-2026-96453
      evidence: When a custom truststore is provided to verify the server identity, the tool incorrectly accepts any self-signed certificate.
---

A vulnerability exists in the Keycloak Admin CLI (kcadm) tool, identified as CVE-2026-96453. The flaw occurs when a custom truststore is provided for server identity verification. In this scenario, the tool incorrectly accepts any self-signed certificate provided the hostname matches the expected value. An attacker with a network-level vantage point can perform a man-in-the-middle (MITM) attack to impersonate the Keycloak server, resulting in the theft of administrative credentials and unauthorized management of the Keycloak instance.

## Impact
Successful exploitation allows for the interception of administrative authentication traffic, leading to the compromise of credentials and the potential for unauthorized management of the Keycloak server.

## Recommendation
- Inventory environments utilizing the Keycloak Admin CLI (kcadm) tool for automated or manual administrative tasks.
- Audit automation scripts to identify those that specify a custom truststore (via the --truststore or equivalent configuration parameters).
- Review network traffic patterns for administrative CLI activity to detect potential MITM anomalies or spoofed endpoint responses until a vendor-supplied patch is applied.
- Monitor vendor security advisories for the release of a patched version of Keycloak and the associated CLI tooling.
