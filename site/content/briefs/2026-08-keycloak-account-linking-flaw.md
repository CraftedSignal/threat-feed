---
title: Account Takeover Vulnerability in Keycloak Legacy Account-Linking Endpoint
slug: 2026-08-keycloak-account-linking-flaw
description: Keycloak suffers from a vulnerability in its legacy client-initiated account-linking endpoint where predictable hashes allow attackers to forge linking URLs, facilitating unauthorized account takeover.
date: "2026-08-18T23:08:54Z"
lastmod: "2026-08-19T16:34:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: By tricking a user into authenticating, an attacker-controlled client can forge a valid linking URL to connect the victim's account to an attacker's external identity.
    confidence_band: high
cves:
  - id: CVE-2026-15571
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15571
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2915
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Keycloak instances to address CVE-2026-15571
      owner: IT Operations
      due: 72h
      evidence: NVD vulnerability notice CVE-2026-15571
  enrichment_needed:
    - item: CVE-2026-15571
      owner: CTI
      reason: Monitor for exploit code publication
      evidence: NVD vulnerability entry
updates:
  - at: "2026-08-19T16:34:43Z"
    level: L2
    summary: added CVE-2026-15571
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2915
---

A security vulnerability (CVE-2026-15571) exists in the legacy client-initiated account-linking endpoint of Keycloak, an open-source identity and access management solution. The vulnerability stems from an insecure protection mechanism that relies on a hash which can be predicted by an attacker operating a malicious OpenID Connect (OIDC) client.

By forcing or tricking an authenticated victim into accessing a crafted link, an attacker can manipulate the account-linking process. The predictable hash allows the attacker to forge a valid linking URL that associates the victim's identity with an external identity provider controlled by the attacker. Upon successful exploitation, the attacker gains full control over the victim's account, including the ability to perform actions or log in as the victim within the targeted organization. Organizations utilizing legacy account-linking features in Keycloak should review their configuration and upgrade to versions where this endpoint is secured or disabled.

## Impact

Successful exploitation leads to a complete account takeover of the targeted victim, potentially affecting any sector that relies on Keycloak for identity and access management. The impact is significant as it grants the attacker persistent access and the ability to impersonate legitimate users, which can lead to data exfiltration or lateral movement within the enterprise environment.

## Recommendation

- Identify all instances of Keycloak currently in production environments.
- Review Keycloak documentation to determine if the legacy client-initiated account-linking endpoint is currently enabled.
- Disable the legacy account-linking endpoint if not strictly required for business operations.
- Apply security patches or updates provided by the Keycloak project addressing CVE-2026-15571.
- Monitor logs for unusual account-linking events or repeated authorization failures associated with OIDC client workflows.
