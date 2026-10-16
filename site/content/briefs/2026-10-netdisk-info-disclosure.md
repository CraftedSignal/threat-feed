---
title: Information Disclosure in netdisk-fast-download via Hard-Coded Credentials
slug: 2026-10-netdisk-info-disclosure
description: The netdisk-fast-download package through 0.4.8 contains an information disclosure vulnerability that allows unauthenticated attackers to decrypt cloud-drive credentials via a hard-coded AES key.
date: "2026-10-16T18:46:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netdisk-fast-download:netdisk-fast-download:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - information-disclosure
  - vulnerability-management
products:
  - netdisk-fast-download (<= 0.4.8)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Unauthenticated attackers can retrieve donated netdisk credentials... and decrypt the encryptedAuth blob using the hard-coded AES key.
    confidence_band: high
cves:
  - id: CVE-2026-111612
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111612
rules:
  - title: Detect CVE-2026-111612 Exploitation - Unauthorized Access to /v2/randomAuth
    description: Detects potential exploitation attempts targeting the /v2/randomAuth endpoint in the netdisk-fast-download ParserApi.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade netdisk-fast-download to a version beyond 0.4.8
      owner: IT Operations
      due: 48h
      evidence: Source CVE details
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version > 0.4.8
      owner: IT Operations
      addresses: CVE-2026-111612
      evidence: Source advisory
---

The netdisk-fast-download package, specifically versions through 0.4.8, contains a critical information disclosure vulnerability within its ParserApi. Unauthenticated attackers can interact with the /v2/randomAuth endpoint to retrieve encrypted credential blobs. These blobs are secured using a hard-coded AES key, identified as 'nfd_auth_key2026', which is embedded directly within the application code. By performing a simple decryption of the intercepted blob using this static key, an unauthorized party can successfully recover sensitive data belonging to other users. Exposed data includes cloud-drive cookies, authentication tokens, and potentially plain-text passwords. This vulnerability poses a significant risk to user privacy and account security, as it allows for trivial credential harvesting without requiring prior access or specific user interaction.

## Impact

The vulnerability directly impacts the confidentiality of user cloud-drive accounts. Successful exploitation grants attackers unauthorized access to victim credentials, enabling them to hijack cloud sessions, exfiltrate sensitive files, or maintain persistence within the victim's storage environment. This issue affects all users running versions of netdisk-fast-download up to and including 0.4.8. Given the nature of the exposed information, this could lead to broad-scale account compromise across the user base.

## Recommendation

Prioritize the immediate update of netdisk-fast-download to a version beyond 0.4.8 where this hard-coded key has been remediated. Monitor network traffic logs for repeated unauthorized access attempts to the /v2/randomAuth endpoint of the ParserApi. Ensure that any suspected exposure of cloud-drive credentials leads to immediate session invalidation and password rotation for affected accounts.
