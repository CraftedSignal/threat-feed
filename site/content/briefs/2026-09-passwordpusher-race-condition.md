---
title: 'CVE-2026-87816: TOCTOU Race Condition in PasswordPusher View Limit Enforcement'
slug: 2026-09-passwordpusher-race-condition
description: PasswordPusher versions prior to 2.11.1 contain a race condition in view limit enforcement, allowing unauthenticated attackers to bypass 'expire_after_views' restrictions and access one-time secrets multiple times through concurrent requests.
date: "2026-09-09T12:57:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:passwordpusher:passwordpusher:*:*:*:*:*:*:*:*
vendors:
  - PasswordPusher
products:
  - PasswordPusher (< 2.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Unauthenticated attackers can send concurrent requests to the show endpoint to access one-time secrets multiple times.
    confidence_band: high
cves:
  - id: CVE-2026-87816
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87816
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade PasswordPusher to version 2.11.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies 2.11.1 as the fix version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.11.1
      owner: IT Operations
      addresses: CVE-2026-87816
      evidence: NVD advisory for CVE-2026-87816
---

PasswordPusher versions before 2.11.1 contain a time-of-check-to-time-of-use (TOCTOU) race condition in the logic responsible for enforcing 'expire_after_views' limits. This vulnerability impacts the application's ability to properly invalidate one-time secrets after they have been accessed the configured number of times. By sending high-concurrency requests to the show endpoint, an unauthenticated attacker can retrieve a secret multiple times before the backend application process increments the view counter and marks the object as expired. This failure in synchronization effectively neutralizes the primary security feature of the PasswordPusher platform, which is designed to ensure sensitive data is only viewed once or a limited number of times. Defenders should prioritize patching, as this vulnerability allows for the unauthorized extraction of credentials or secrets that were intended to be transient.

## Impact

Successful exploitation allows unauthenticated users to bypass security controls designed to limit secret access. This leads to the unauthorized exfiltration of sensitive information, such as credentials or API keys, stored in PasswordPusher, violating the intended data expiration policies. Any organization utilizing PasswordPusher for secure transmission of secrets is at risk of credential theft if an attacker has visibility into the secret links.

## Recommendation

- Upgrade all PasswordPusher instances to version 2.11.1 or later to remediate the TOCTOU race condition in the view limit enforcement logic.
- Review access logs for the 'show' endpoint to identify patterns of high-frequency or concurrent requests from single IP addresses targeting the same secret URL, which may indicate exploitation attempts.
- Implement rate-limiting at the reverse proxy or WAF layer to mitigate the impact of high-concurrency request floods used to trigger race conditions.
