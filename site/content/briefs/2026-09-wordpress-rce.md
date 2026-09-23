---
title: Unauthenticated Remote Code Execution in WordPress
slug: 2026-09-wordpress-rce
description: CVE-2026-87902 allows unauthenticated remote code execution in WordPress by enabling the loading of arbitrary files outside of legitimate theme directories.
date: "2026-09-23T14:55:51Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - rce
  - vulnerability
vendors:
  - WordPress
products:
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability can be used by an attacker without login credentials to load a special file outside the normal themes of WordPress.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can lead to the attacker being able to execute their own code on the server where the WordPress website runs.
    confidence_band: high
cves:
  - id: CVE-2026-87902
    cvss: 8.1
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheid-in-wordpress-kan-leiden-tot-servermisbruik-update-nu
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all WordPress instances to the latest secure version referenced in the vendor advisory.
      owner: IT Operations
      due: 24h
      evidence: The supplier has released a security update. It is important to install this update as soon as possible.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WordPress to the version specified in the vendor security advisory.
      owner: IT Operations
      addresses: CVE-2026-87902
      evidence: See the security advisory from WordPress for vulnerable version numbers.
---

A critical vulnerability (CVE-2026-87902) has been identified in WordPress that permits unauthenticated attackers to achieve remote code execution (RCE) on the underlying server. The flaw stems from an improper file handling mechanism that allows an attacker to bypass standard theme constraints and trigger the loading of files from unauthorized locations. When combined with other server-side configurations, this vulnerability can lead to full server compromise, allowing attackers to access, modify, or delete confidential data, and potentially utilize the host server for further malicious activities. While there are currently no reports of active exploitation or public exploit code, the severity of the potential impact necessitates immediate patching. Organizations are advised to verify their WordPress versions against the official vendor security advisory and apply the provided updates immediately.

## Impact

Successful exploitation of CVE-2026-87902 grants an attacker the ability to execute arbitrary code with the privileges of the web server user. This can result in complete loss of confidentiality, integrity, and availability for the hosted WordPress site. Potential consequences include unauthorized data access or exfiltration, data manipulation, and the hijacking of the server for hosting malicious content or participating in further network attacks.

## Recommendation

* Immediately identify and patch all WordPress instances to the version specified in the official WordPress security advisory.
* If the specific version is unknown, contact your IT service provider to audit the environment for vulnerable WordPress installations.
* Monitor web server logs for suspicious requests involving unexpected directory traversal or non-standard file loading patterns.
