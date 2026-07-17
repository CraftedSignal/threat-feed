---
title: CVE-2026-62202 - OpenClaw Privilege Escalation via Isolated Cron Jobs
slug: 2026-07-openclaw-privilege-escalation
description: OpenClaw versions 2026.6.1 before 2026.6.9 contain a privilege escalation vulnerability, CVE-2026-62202, in isolated cron jobs that allows lower-trust callers to regain denied execution tools and execute or persist actions beyond their intended authorization by leveraging misconfigured input paths.
date: "2026-07-17T02:22:20Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - privilege-escalation
  - vulnerability
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.6.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: OpenClaw versions 2026.6.1 before 2026.6.9 contain a privilege escalation vulnerability in isolated cron jobs that allows lower-trust callers to regain denied execution tools.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Attackers can execute or persist actions beyond their intended authorization by leveraging misconfigured input paths in the affected cron feature.
    confidence_band: high
cves:
  - id: CVE-2026-62202
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62202
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-mm9g-83wh-mhwj
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-cron
---

OpenClaw versions 2026.6.1 through 2026.6.8 are affected by a high-severity privilege escalation vulnerability, tracked as CVE-2026-62202, located within the isolated cron job feature. This flaw permits users or processes with lower trust to bypass intended authorization and re-enable execution tools that were previously denied to them. Attackers can leverage misconfigured input paths within this cron functionality to execute commands or establish persistence on the system with elevated privileges. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a critical risk if exploited. There is currently no public information suggesting active exploitation of this vulnerability in the wild; however, its nature allows for significant impact upon successful exploitation.

## Attack Chain

1. An attacker identifies an OpenClaw instance running an affected version (2026.6.1 through 2026.6.8).
2. The attacker obtains initial access to the system where OpenClaw is installed, operating with lower-trust privileges.
3. The attacker then identifies specific isolated cron jobs with misconfigured input paths within the OpenClaw environment.
4. By providing specially crafted input to these identified misconfigured paths, the attacker circumvents the normal authorization checks.
5. This bypass allows the attacker to regain access to or modify execution tools and capabilities that were intended to be restricted for their current trust level.
6. The vulnerable cron job then executes the attacker's manipulated actions or commands with elevated privileges, achieving unauthorized code execution or establishing persistence.

## Impact

Successful exploitation of CVE-2026-62202 results in privilege escalation, allowing a lower-trust attacker to gain higher access levels on the compromised system. This enables attackers to execute arbitrary code, modify system configurations, install malicious software, or establish persistent access beyond their initial authorization. While specific victim numbers or targeted sectors are not available, any organization utilizing vulnerable OpenClaw installations is at risk. The direct consequence for a compromised system is a loss of integrity and confidentiality, with potential for full system control.

## Recommendation

* Immediately upgrade all OpenClaw installations to version 2026.6.9 or later to patch CVE-2026-62202.
* Review cron job configurations within OpenClaw to ensure input paths are correctly secured and adhere to the principle of least privilege, as specified in the vendor's updated documentation.
