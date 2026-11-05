---
brief_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
event_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
revision: 4
activity_at: "2026-11-05T08:54:12Z"
revision_history:
  - revision: 2
    at: "2026-11-03T04:05:53Z"
    checksum: sha256:91e4c05562b77df30716736c2209223a93a0a5b6d4e2abf4fefa70ea6d9723e9
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-11-03T21:28:45Z"
    checksum: sha256:283c7c423a0581b9469fd2a4c7bef8b8f017fa0b6b210b25adb7b8c89cf08d53
    summary: added coverage for GS1900 series switches +3 products
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority_signals
      - qa_status
      - references
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
  - revision: 4
    at: "2026-11-05T08:54:12Z"
    checksum: sha256:666c248a3466c109f10d557bb65062f5dbfa188a41c58b2964d11ff71fde3a28
    summary: severity → critical
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - priority_score
      - priority_signals
      - references
      - severity
      - summary
      - tags
      - threat_actor
      - title
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/zyxel-gs1900-patch-fails-to-block-zero.html
title: 'Zyxel GS1900 Series: Unauthenticated Remote Command Execution (CVE-2026-107441)'
slug: 2026-11-zyxel-gs1900-24e-oob-write
description: Zyxel GS1900 series switches are vulnerable to unauthenticated remote code execution due to an out-of-bounds write in the web management interface that persists in previously patched firmware, facilitating credential theft and configuration harvesting by the Red Heron threat actor.
date: "2026-11-03T03:50:17Z"
lastmod: "2026-11-05T08:52:11Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
actors:
  - Red Heron
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Advisory details are sparse regarding specific CVE IDs; recommend following vendor advisory links for latest technical updates.
cpes:
  - cpe:2.3:a:zyxel:gs1900_24e:*:*:*:*:*:*:*:*
  - cpe:2.3:a:zyxel:nwa110ax:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - network-security
  - rce
  - root-access
vendors:
  - Zyxel
products:
  - GS1900-24E (through firmware 2.90(AAHK.2)C0)
  - NWA110AX (<= 7.12)
  - GS1900 series switches
  - APs
  - FWA7
  - Security Routers
  - GS1900-8 (2.90(AAHH.2)C0 and earlier)
  - GS1900-8HP (2.90(AAHI.2)C0 and earlier)
  - GS1900-10HP (2.90(AAZI.2)C0 and earlier)
  - GS1900-16 (2.90(AAHJ.2)C0 and earlier)
  - GS1900-24 (2.90(AAHL.2)C0 and earlier)
  - GS1900-24E (2.90(AAHK.2)C0 and earlier)
  - GS1900-24EP (2.90(ABTO.2)C0 and earlier)
  - GS1900-24HPv2 (2.90(ABTP.2)C0 and earlier)
  - GS1900-48 (2.90(AAHN.2)C0 and earlier)
  - GS1900-48HPv2 (2.90(ABTQ.2)C0 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The exploit lets anyone who can reach a switchs web management interface run commands on it without logging in.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attackers used the exploit to download a data-collection script onto the switches.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The data included switch configurations, hashed root credentials, and network information.
    confidence_band: high
cves:
  - id: CVE-2026-107441
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-76955
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107441
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=CVE-2026-76955
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-buffer-overflow-vulnerability-in-certain-aps-fwa7-and-security-routers-11-03-2026
  - https://sploitus.com/exploit?id=CVE-2026-76955&utm_source=rss&utm_medium=rss
  - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-out-of-bounds-write-vulnerability-in-gs1900-series-switches-11-03-2026
  - https://thehackernews.com/2026/11/zyxel-gs1900-patch-fails-to-block-zero.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Zyxel GS1900 switches to the 2.90 Patch 3 firmware.
      owner: IT Operations
      due: 24h
      evidence: Zyxel security advisory confirms Patch 3 closes the CVE-2026-107441 vulnerability.
    - action: Restrict management interface access to internal management subnets via firewall.
      owner: IT Operations
      due: 48h
      evidence: Advisory states attacker only needs network reachability to the management service.
  hunt_leads:
    - lead: Identify GS1900 switches showing outbound connection attempts to unknown external IPs or presence of unauthorized shell scripts in configuration files.
      technique_id: T1059
      data_needed:
        - Firewall egress logs
        - Device configuration snapshots
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers used the exploit to download a data-collection script and pick up data.
  mitigation_plan:
    - priority: immediate
      action: Check Zyxel security portal for latest firmware updates for GS1900 series, APs, FWA7, and security routers
      owner: IT Operations
      addresses: Out-of-bounds write and buffer overflow vulnerabilities
      evidence: Zyxel security advisory AV26-1114
    - priority: immediate
      action: Upgrade to 2.90 Patch 3 firmware as specified for each model.
      owner: IT Operations
      addresses: CVE-2026-107441
      evidence: Vendor advisory identifies Patch 3 as the definitive fix.
updates:
  - at: "2026-11-03T04:05:16Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - at: "2026-11-03T21:28:09Z"
    level: L2
    summary: added CVE-2026-76955
    sources:
      - sploitus
  - at: "2026-11-03T21:28:09Z"
    level: L1
    summary: added coverage for GS1900 series switches +3 products
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
  - at: "2026-11-05T08:52:11Z"
    level: L3
    summary: severity → critical
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/zyxel-gs1900-patch-fails-to-block-zero.html
---

Research by Binarly has identified that Zyxel GS1900 network switches remain vulnerable to unauthenticated remote command execution despite the application of previous security patches (Patch 2). The vulnerability, tracked as CVE-2026-107441, stems from an out-of-bounds write in the switch's web management interface. 

The flaw exists because input validation logic in the Patch 2 firmware occurs only after the memory corruption has already triggered, allowing an attacker to overwrite internal control variables and redirect execution flow to attacker-supplied commands. Zyxel has released Patch 3 firmware to remediate this issue.

## Attack Chain

1. Attacker identifies internet-exposed GS1900 switch management interface.
2. Attacker sends a crafted HTTP request with an oversized 140th parameter to the web management service.
3. The service performs an out-of-bounds write, overwriting the parameter counter and subsequent memory.
4. The attacker achieves arbitrary code execution with root privileges.
5. The attacker downloads and executes a data-collection script.
6. The script harvests configuration data and hashed root credentials from the device.
7. Data is staged for exfiltration via the web interface.

## Impact

Successful exploitation allows unauthenticated attackers to gain root-level access to the switch. Observed impact includes the exfiltration of device configurations and hashed root credentials. Attackers have been observed targeting these devices to perform mass data collection, with a high proportion of affected devices identified as still running factory-default credentials.

## Recommendation

1. Immediately apply the 2.90 Patch 3 firmware update to all Zyxel GS1900 models listed in the advisory.
2. Inventory all internet-exposed network management interfaces and restrict access to these services to trusted management subnets via firewall rules.
3. Audit all GS1900 switches for evidence of unauthorized persistent scripts or modified configuration files.
4. Rotate all credentials on any GS1900 switches that were reachable via the internet prior to patching, particularly those where default credentials remained in use.
