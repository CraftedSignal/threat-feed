---
title: 'CVE-2026-111636: Authentication Bypass in OpenBMB StaffDeck'
slug: 2026-10-openbmb-staffdeck-auth-bypass
description: OpenBMB StaffDeck versions through 0.5.6 contain an authentication bypass vulnerability allowing attackers to forge administrator session tokens via a hard-coded app_secret.
date: "2026-10-16T18:47:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbmb:staffdeck:*:*:*:*:*:*:*:*
vendors:
  - OpenBMB
products:
  - StaffDeck (<= 0.5.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can sign an HMAC-SHA256 token for the seeded 'admin' user in 'tenant_demo' to gain full tenant administration.
    confidence_band: high
cves:
  - id: CVE-2026-111636
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111636
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all instances of StaffDeck to the latest version to remediate CVE-2026-111636.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111636 advisory.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to StaffDeck instances to prevent unauthorized external access.
      owner: IT Operations
      addresses: CVE-2026-111636
      evidence: Unauthenticated attacker vector.
---

OpenBMB StaffDeck through version 0.5.6 contains a critical authentication bypass vulnerability (CVE-2026-111636) resulting from the use of a hard-coded default application secret. Because this secret is embedded in the application code rather than dynamically generated, an unauthenticated attacker can perform unauthorized HMAC-SHA256 signing of session tokens. By crafting a token for the 'admin' user within the 'tenant_demo' context, an attacker can bypass all authentication mechanisms to obtain full administrative access to the platform. This access allows the actor to manage stored model configurations and sensitive channel credentials, leading to full tenant compromise. Given the ease of exploitation, this vulnerability poses a significant risk to the confidentiality and integrity of deployments.

## Impact

Successful exploitation grants an attacker full administrative control over a StaffDeck tenant. Impacted organizations face potential exfiltration of sensitive model data, compromise of channel integration credentials, and unauthorized control over platform operations. The severity is marked as high (CVSS 8.1), reflecting the potential for complete account takeover and data breach within affected environments.

## Recommendation

Prioritize the immediate update of all StaffDeck instances to a version beyond 0.5.6 that resolves the hard-coded secret vulnerability. As a temporary mitigation, ensure that the application is not exposed to the public internet and verify that the 'tenant_demo' is not utilized in production environments.
