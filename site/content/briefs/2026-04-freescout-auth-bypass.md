---
title: FreeScout Incorrect Authorization Vulnerability via Save Draft
slug: 2026-04-freescout-auth-bypass
description: FreeScout before 1.8.215 has an incorrect authorization vulnerability where a direct POST request to the `save_draft` AJAX path can create a draft inside a hidden conversation when `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` is enabled, potentially allowing unauthorized access or modification of data.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - authorization
  - web application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41190
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41190
  - https://github.com/freescout-help-desk/freescout/commit/414878eb79be7cb01a3ae124df6efcd23729275f
  - https://github.com/freescout-help-desk/freescout/releases/tag/1.8.215
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-vj2p-2789-3747
iocs:
  - type: url
    value: https://github.com/freescout-help-desk/freescout/commit/414878eb79be7cb01a3ae124df6efcd23729275f
  - type: url
    value: https://github.com/freescout-help-desk/freescout/releases/tag/1.8.215
  - type: url
    value: https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-vj2p-2789-3747
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect FreeScout Save Draft Abuse
    description: Detects POST requests to the save_draft endpoint in FreeScout, potentially indicating an attempt to exploit CVE-2026-41190
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: FreeScout Unauthorized Draft Creation Attempt
    description: Detects suspicious POST requests to the FreeScout save_draft endpoint with a high data volume, potentially indicating an attempt to create a large or malicious draft.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout is a self-hosted help desk and shared mailbox platform. Prior to version 1.8.215, a vulnerability exists related to authorization controls when the `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` setting is enabled. Specifically, the `save_draft` AJAX endpoint lacks proper authorization checks. This allows an attacker to potentially bypass intended access restrictions and create drafts within conversations that they should not be able to access, leading to unauthorized modification or viewing of conversation data. This vulnerability was addressed in version 1.8.215.

## Attack Chain

1.  Attacker identifies a FreeScout instance running a version prior to 1.8.215 with `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` enabled.
2.  Attacker authenticates to the FreeScout instance with a valid, but unauthorized user account.
3.  Attacker identifies the conversation ID of a conversation they are not assigned to and cannot normally access via the UI.
4.  Attacker crafts a POST request to the `/index.php?m=conversations&a=save_draft` endpoint, including the conversation ID and the draft content they wish to create.
5.  The server, lacking proper authorization checks on the `save_draft` endpoint, accepts the POST request.
6.  A draft is created within the targeted conversation, associated with the attacker's user account.
7.  The attacker, or potentially other unauthorized users who later gain access to the attacker's account, can view or modify the drafted content, potentially exfiltrating sensitive information.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to create drafts within conversations they are not assigned to. This could lead to the unauthorized viewing or modification of sensitive information contained within the conversations, potentially leading to data breaches or compliance violations. The vulnerability affects FreeScout instances running versions prior to 1.8.215 with the specific `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` setting enabled.

## Recommendation

*   Upgrade FreeScout to version 1.8.215 or later to remediate the vulnerability (references: https://github.com/freescout-help-desk/freescout/releases/tag/1.8.215).
*   Monitor web server logs for POST requests to the `/index.php?m=conversations&a=save_draft` endpoint originating from unusual IP addresses or user agents using the Sigma rule provided below.
*   Implement web application firewall (WAF) rules to filter or block unauthorized POST requests to the vulnerable endpoint.
