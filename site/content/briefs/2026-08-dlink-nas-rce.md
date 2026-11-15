---
brief_id: brief-2026-08-dlink-nas-rce
event_id: brief-2026-08-dlink-nas-rce
revision: 2
activity_at: "2026-11-15T22:07:33Z"
revision_history:
  - revision: 2
    at: "2026-11-15T22:07:33Z"
    checksum: sha256:fb39798f82c633b3d80f263b191aac0b0f6868dea804e64e718a03e13396e1f9
    summary: 'added detection rule: Detect CVE-2024-10914 Exploitation Attempt'
    changed_fields:
      - content
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority_signals
      - references
      - rules
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EGI08-CVE-2024-10914&utm_source=rss&utm_medium=rss
title: 'D-Link NAS: Remote Code Execution via cgi_user_add (CVE-2024-10914)'
slug: 2026-08-dlink-nas-rce
description: A critical OS command injection vulnerability in the cgi_user_add function of D-Link NAS devices allows unauthenticated remote attackers to execute arbitrary commands.
date: "2026-08-17T14:54:35Z"
lastmod: "2026-11-15T22:07:18Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:h:dlink:dns-320:20241028:*:*:*:*:*:*:*
  - cpe:2.3:h:dlink:dns-320lw:20241028:*:*:*:*:*:*:*
  - cpe:2.3:h:dlink:dns-325:20241028:*:*:*:*:*:*:*
  - cpe:2.3:h:dlink:dns-340l:20241028:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-320_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-320lw_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-325_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dlink:dns-340l_firmware:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EGI08-CVE-2024-10914&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - nas
  - hardware
  - vulnerability
  - rce
  - webserver
  - dlink
vendors:
  - D-Link
products:
  - DNS-320
  - DNS-320LW
  - DNS-325
  - DNS-340L
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /cgi-bin/account_mgr.cgi script on several D-Link NAS devices is vulnerable to unauthenticated command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument name leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2024-10914
    cvss: 8.1
    epss: 0.97391
    kev_status: "false"
references:
  - https://www.exploit-db.com/exploits/52643
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10914
  - https://cveawg.mitre.org/api/cve/CVE-2024-10914
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EGI08-CVE-2024-10914
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EGI08-CVE-2024-10914&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2024-10914 Exploitation Attempt
    description: Detects HTTP requests to /cgi-bin/account_mgr.cgi where the name parameter contains common shell command injection characters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-11-15T22:07:18Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2024-10914 Exploitation Attempt'
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EGI08-CVE-2024-10914&utm_source=rss&utm_medium=rss
---

### Overview
A critical OS command injection vulnerability exists in D-Link DNS-320, DNS-320LW, DNS-325, and DNS-340L devices with firmware versions up to 20241028. The vulnerability is located in the `cgi_user_add` function of the `/cgi-bin/account_mgr.cgi` endpoint. Manipulation of the `name` argument allows unauthenticated remote attackers to inject and execute arbitrary OS commands. Public proof-of-concept exploit code has been disclosed.

### Attack Chain
The vulnerability is exploitable via a network-based HTTP request targeting the `account_mgr.cgi` script. By injecting shell metacharacters into the `name` query parameter, an attacker can trigger command execution within the context of the underlying web server.

### Impact
Successful exploitation results in arbitrary OS command execution on the target device, leading to a full system compromise. The vulnerability is rated with a CVSSv4.0 base score of 9.2 (Critical).

### Recommendation
No official patch or firmware update is currently identified as a remediation in the available CVE data. Users are advised to monitor the environment for unauthorized access to the web management interface and restrict exposure of these devices to the public internet.
