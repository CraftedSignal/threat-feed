---
title: NetNTLM Hash Phishing via Archive Extraction (CVE-2025-59284)
slug: 2026-03-netntlm-phishing
description: A phishing technique, potentially still viable due to incomplete patching, allows attackers to obtain NetNTLM hashes from archive extraction on Windows systems (CVE-2025-59284).
date: "2026-03-18T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - credential-access
  - netntlm
  - phishing
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
references:
  - https://www.reddit.com/r/netsec/comments/1rwguw8/cve202559284_how_reading_a_gnu_manpage_led_to_a/
  - https://sec-fault.com/blog/cve-2025-59284/
rules:
  - title: Detect Suspicious Outbound NTLM Authentication
    description: Detects outbound NTLM authentication attempts to non-local or unusual domains, indicative of potential NTLM relay or credential theft attacks.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - network_connection
      - windows
  - title: Detect UNC Path in Archive Files
    description: Detects archive files containing UNC paths, which could be used to trigger NTLM authentication to a malicious server.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A vulnerability, tracked as CVE-2025-59284, enables attackers to capture NetNTLM hashes from Windows systems through a specially crafted archive file. This technique exploits how Windows handles file extraction, potentially forcing authentication requests to a malicious server controlled by the attacker. The vulnerability was presented at BsidesLjubljana in March 2026, suggesting recent active research and potential exploitation. The original Reddit post indicates that the Microsoft patch might…
