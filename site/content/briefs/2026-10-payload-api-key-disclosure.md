---
title: Payload API Key Disclosure via Document Read Access
slug: 2026-10-payload-api-key-disclosure
description: A vulnerability in Payload CMS versions 3.x and 4.x-canary allows unauthorized users with document read permissions to access active API keys stored within authentication collections.
date: "2026-10-06T18:47:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:payloadcms:payload:*:*:*:*:*:node.js:*:*
vendors:
  - Payload
products:
  - payload (>= 3.0.0 < 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Users with read access to other user documents could access their active API keys.
    confidence_band: high
cves:
  - id: CVE-2026-105849
references:
  - https://github.com/advisories/GHSA-238x-w2j9-gwwr
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105849
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Payload CMS to 3.90.0 or 4.0.0-canary.34
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies these versions for remediation of CVE-2026-105849
  mitigation_plan:
    - priority: immediate
      action: Rotate all API keys generated under affected versions
      owner: Security Team
      addresses: CVE-2026-105849
      evidence: Source recommends rotating any API key that may have been exposed
---

Payload CMS versions prior to 3.90.0 and 4.0.0-canary.34 are vulnerable to an API key disclosure flaw, tracked as CVE-2026-105849. This vulnerability manifests in deployments where the `useAPIKey` authentication feature is enabled. Due to insecure access control logic, users who possess read access to documents within an authentication collection can view sensitive API keys belonging to other users. Because these keys hold the permissions of the target account, successful exploitation allows an attacker to masquerade as the compromised user until the key is rotated or disabled. This impacts organizations relying on Payload for authentication and document management, particularly those with permissive document access policies.

## Impact

Successful exploitation allows unauthorized users to retrieve valid API keys of other users, leading to account takeover. The impact is significant for applications where API keys manage sensitive operations or provide access to protected administrative functions. Users must immediately verify document read permissions and rotate any keys potentially exposed during the window of vulnerability.

## Recommendation

* Upgrade Payload CMS to version 3.90.0 or 4.0.0-canary.34 to patch CVE-2026-105849.
* Audit document read permissions in the CMS and restrict access to authentication collections to authorized users only.
* Disable the `useAPIKey` feature if not strictly required for application functionality.
* Perform a mandatory rotation of all active API keys generated while the affected versions were in use to mitigate potential unauthorized access.
