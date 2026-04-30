---
title: OpenClaw Microsoft Teams Plugin Sender Allowlist Bypass (CVE-2026-34506)
slug: 2026-03-openclaw-allowlist-bypass
description: OpenClaw before 2026.3.8 contains a sender allowlist bypass vulnerability in its Microsoft Teams plugin, allowing unauthorized senders to bypass intended authorization checks due to improper handling of empty groupAllowFrom parameters, potentially leading to information disclosure.
date: "2026-03-31T12:16:30Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-34506
  - openclaw
  - microsoft teams
  - allowlist bypass
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34506
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34506
  - https://github.com/openclaw/openclaw/commit/88aee9161e0e6d32e810a25711e32a808a1777b2
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g7cr-9h7q-4qxq
  - https://www.vulncheck.com/advisories/openclaw-sender-allowlist-bypass-in-microsoft-teams-plugin-via-route-allowlist-configuration
rules:
  - title: Detect OpenClaw Route Allowlist Misconfiguration
    description: Detects when OpenClaw is configured with an empty 'groupAllowFrom' parameter in a team/channel route allowlist.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect Unauthorized Sender in OpenClaw Allowlisted Route
    description: Detects messages from unauthorized senders in OpenClaw allowlisted routes when the 'groupAllowFrom' parameter is empty.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw, a Microsoft Teams plugin, is vulnerable to a sender allowlist bypass (CVE-2026-34506) in versions prior to 2026.3.8. The vulnerability stems from a misconfiguration issue where an empty `groupAllowFrom` parameter in the team/channel route allowlist leads to the synthesis of wildcard sender authorization. This allows any sender within the matched team/channel to trigger replies in allowlisted Teams routes, effectively bypassing intended authorization checks. This vulnerability was…
