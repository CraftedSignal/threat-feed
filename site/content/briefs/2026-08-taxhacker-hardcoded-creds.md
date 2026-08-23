---
title: Hard-coded Credential Vulnerability in TaxHacker
slug: 2026-08-taxhacker-hardcoded-creds
description: TaxHacker versions 0.8.2 and earlier contain a hard-coded credential vulnerability in the JWT Secret Handler, allowing potential remote exploitation via the BETTER_AUTH_SECRET argument.
date: "2026-08-23T05:35:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - hardcoded-credentials
  - authentication-bypass
vendors:
  - vas3k
products:
  - TaxHacker (0.8.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The manipulation of the argument BETTER_AUTH_SECRET leads to hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-78062
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78062
  - https://github.com/vas3k/TaxHacker/issues/147
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internal TaxHacker deployments and restrict exposure if possible.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78062 affects TaxHacker <= 0.8.2
  enrichment_needed:
    - item: Patch availability
      owner: CTI
      reason: Monitor the GitHub issue for official remediation.
      evidence: https://github.com/vas3k/TaxHacker/issues/147
  mitigation_plan:
    - priority: immediate
      action: Rotate any existing secrets if the application was ever exposed to untrusted networks.
      owner: IT Operations
      addresses: CVE-2026-78062
      evidence: Hard-coded credentials vulnerability
---

A vulnerability (CVE-2026-78062) has been identified in the TaxHacker project, specifically within versions up to 0.8.2. The vulnerability resides in the JWT Secret Handler component, located in the lib/config.ts file. The envSchema.parse function improperly handles the BETTER_AUTH_SECRET argument, resulting in the usage of hard-coded credentials for authentication secrets. An attacker can exploit this remotely to bypass authentication mechanisms or forge JWTs. The issue was disclosed via a GitHub issue report, but as of the publication date, the maintainers have not issued a patch. Defenders should treat this as a high-risk exposure if TaxHacker is deployed in production environments where JWT security is critical.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to gain access to hard-coded secrets. In the context of a JWT Secret Handler, this typically leads to the ability to forge, sign, or decrypt JSON Web Tokens, potentially resulting in unauthorized administrative access, privilege escalation, or data exfiltration across systems relying on these tokens for identity verification.

## Recommendation

Prioritized, concrete actions for security teams:
- Audit all deployments of TaxHacker to confirm the version is 0.8.2 or earlier.
- Implement strict network segmentation or Web Application Firewall (WAF) rules to restrict access to the TaxHacker application if it cannot be immediately patched or removed.
- Monitor application logs for anomalous requests to endpoints that handle authentication or token generation until the vendor releases a fix.
- Check the project repository (https://github.com/vas3k/TaxHacker/issues/147) for updates on a vendor-provided fix or manual workarounds.
