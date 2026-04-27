---
title: OpenClaw Allowlist Bypass Vulnerability (CVE-2026-35666)
slug: 2026-04-openclaw-bypass
description: OpenClaw before 2026.3.22 contains an allowlist bypass vulnerability (CVE-2026-35666) in system.run approvals that fails to properly handle /usr/bin/time wrappers, allowing attackers to bypass executable binding restrictions.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - cve
  - allowlist-bypass
  - execution
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-35666
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35666
  - https://github.com/openclaw/openclaw/commit/39409b6a6dd4239deea682e626bac9ba547bfb14
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-qm9x-v7cx-7rq4
  - https://www.vulncheck.com/advisories/openclaw-allowlist-bypass-via-unregistered-time-dispatch-wrapper
rules:
  - title: Detect Execution via Unregistered Time Wrapper
    description: Detects the execution of commands using unregistered /usr/bin/time wrappers, potentially bypassing allowlist restrictions in OpenClaw.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Unregistered Time Executable Creation
    description: Detects the creation of new executable files in /tmp or other common writable directories that have 'time' in the name.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a security-focused application, is susceptible to an allowlist bypass vulnerability affecting versions prior to 2026.3.22.  This flaw, identified as CVE-2026-35666, resides within the system.run approval mechanism, specifically in its handling of `/usr/bin/time` wrappers. The vulnerability stems from the system's failure to properly unwrap these wrappers, leading to an exploitable condition where attackers can circumvent intended executable binding restrictions. By employing an…
