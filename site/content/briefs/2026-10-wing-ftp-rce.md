---
brief_id: brief-2026-10-30-wing-ftp-rce
event_id: brief-2026-10-30-wing-ftp-rce
revision: 2
activity_at: "2026-11-19T16:15:02Z"
revision_history:
  - revision: 2
    at: "2026-11-19T16:15:02Z"
    checksum: sha256:913afd19ab3eaa9433e37b8339f4ca4c551dfb1040efb275d3d89fb9ba572748
    summary: exploited:true; KEV CVE-2025-47812
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: 'Wing FTP Server: Unauthenticated Lua injection remote code execution (CVE-2025-47812)'
slug: 2026-10-wing-ftp-rce
description: An unauthenticated remote code execution vulnerability (CVE-2025-47812) in Wing FTP Server <= 7.4.3 allows attackers to execute arbitrary code via Lua injection into session files by leveraging a NULL byte truncation flaw in username handling.
date: "2026-10-30T08:32:29Z"
lastmod: "2026-11-19T16:14:17Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-07-14T00:00:00Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:wftpserver:wing_ftp_server:*:*:*:*:*:*:*:*
vendors:
  - Wftpserver
products:
  - Wing FTP Server
product_versions:
  - product: Wing FTP Server
    range: <= 7.4.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated Lua injection RCE in Wing FTP Server ≤ 7.4.3 via NULL byte in username.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Hitting any authenticated endpoint (dir.html works) loads that session file via loadfile() -> f(), executing the injected code as root / SYSTEM.
    confidence_band: high
cves:
  - id: CVE-2025-47812
    cvss: 10
    epss: 0.93884
    kev: true
    kev_status: "true"
references:
  - https://github.com/4m3rr0r/CVE-2025-47812-poc
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XS4N4TG-CVE-2025-47812
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XS4N4TG-CVE-2025-47812&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-47812 Exploitation - Web Request with NULL byte and Lua syntax
    description: Detects potential CVE-2025-47812 exploitation by identifying web requests containing NULL byte sequences combined with Lua syntax characters in request parameters
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Wing FTP Server to 7.4.4 or higher
      owner: IT Operations
      due: 24h
      evidence: Wing FTP Server <= 7.4.3 is vulnerable; fixed in 7.4.4
  hunt_leads:
    - lead: Identify successful exploitation by searching for process execution (e.g., cmd.exe, /bin/sh) spawned by the Wing FTP Server process
      technique_id: T1059.003
      data_needed:
        - EDR process creation logs
        - 'Parent process: Wing FTP Server executable'
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit facilitates shell delivery, resulting in netcat callbacks or command execution as SYSTEM/root.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 7.4.4
      owner: IT Operations
      addresses: CVE-2025-47812
      evidence: Fixed in 7.4.4
updates:
  - at: "2026-11-19T16:14:17Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-47812
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Wing FTP Server versions 7.4.3 and earlier are vulnerable to a critical unauthenticated remote code execution (RCE) flaw. The vulnerability exists within the `c_CheckUser()` function, where the username is truncated at the first NULL byte for authentication checks. However, the session creation process writes the full, unsanitized username into a Lua-based session file. By injecting a specially crafted payload containing Lua syntax, an attacker can cause the server to write malicious code into this session file. Accessing any authenticated endpoint subsequently triggers `loadfile()` on the session file, executing the injected Lua code with the privileges of the Wing FTP process (typically SYSTEM on Windows or root on Linux).

## Attack Chain

1. Attacker sends a crafted request to the server containing a NULL byte injected into the username parameter (e.g., `anonymous%00]]<lua>--`).
2. The `c_CheckUser()` authentication function truncates the input at the NULL byte, allowing the request to proceed.
3. The server writes the full, unsanitized username string into a persistent session file.
4. The malicious Lua payload is successfully stored within the session file.
5. The attacker requests an authenticated endpoint, such as `dir.html`.
6. The server loads the session file via `loadfile()`, inadvertently executing the attacker-supplied Lua code.

## Impact

Successful exploitation allows for full system compromise, granting the attacker the same privileges as the Wing FTP Server process, which is often running as root or SYSTEM.

## Recommendation

1. Upgrade Wing FTP Server to version 7.4.4 or later immediately.
2. Inventory all instances of Wing FTP Server in the environment to identify systems running version 7.4.3 or earlier.
3. Monitor web server logs for requests containing NULL bytes or suspicious Lua syntax in the username field.
4. Restrict access to the Wing FTP administrative and web interface ports (defaulting to 5466/5467) to authorized networks only.
