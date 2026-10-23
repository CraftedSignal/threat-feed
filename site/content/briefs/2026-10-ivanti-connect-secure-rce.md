---
brief_id: brief-2026-10-13-ivanti-connect-secure-rce
event_id: brief-2026-10-13-ivanti-connect-secure-rce
revision: 2
activity_at: "2026-10-23T19:51:54Z"
revision_history:
  - revision: 2
    at: "2026-10-23T19:51:54Z"
    checksum: sha256:1e5fc7842c84541c55330cb98a496ccdcda35d20aeaa1ec50e86c1477d120e3a
    summary: connect secure version <= 25.1.1.1, <= 25.1.2.2, <= 22.8R2.4
    changed_fields:
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/ivanti-connect-secure-cve-2026-104935
title: Remote Code Execution Vulnerability in Ivanti Connect Secure
slug: 2026-10-ivanti-connect-secure-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-104935) in Ivanti Connect Secure is being actively exploited in the wild, enabling attackers to gain control over affected systems.
date: "2026-10-13T16:47:01Z"
lastmod: "2026-10-23T19:50:41Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: almost certain
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.8:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-appliance
vendors:
  - Ivanti
products:
  - Connect Secure (22.8R2.4 and older)
  - Connect Secure (25.1.1.1 and older)
  - Connect Secure (25.1.2.2 and older)
  - Connect Secure
  - Connect Secure (<= 25.1.1.1, <= 25.1.2.2, <= 22.8R2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A kwaadwillende kan zonder authenticatie opdrachten uitvoeren op een kwetsbaar Connect Secure-systeem zonder dat daar inloggegevens voor nodig zijn.
    confidence_band: high
cves:
  - id: CVE-2026-104935
    cvss: 8.6
    epss: 0.25982
    kev_status: "false"
references:
  - https://www.ncsc.nl/alerts/zero-day-kwetsbaarheid-in-ivanti-connect-secure-update-direct
  - https://www.cve.org/CVERecord?id=CVE-2026-104935
  - https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935
  - https://pwn.watch/i/ivanti-connect-secure-cve-2026-104935
  - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
  - https://www.ivanti.com/blog/october-2026-security-update
  - https://www.bleepingcomputer.com/news/security/ivanti-warns-of-connect-secure-zero-day-exploited-in-attacks/
  - https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internet-facing Ivanti Connect Secure appliances and verify versions.
      owner: IT Operations
      due: 24h
      evidence: Source advisory on affected version ranges
    - action: Apply firmware updates provided by Ivanti for CVE-2026-104935.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends immediate update
  hunt_leads:
    - lead: Search for unexpected system command execution originating from the web server component of the Connect Secure appliance.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Appliance internal audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated command execution
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patches defined by Ivanti (e.g., 22.8R2.5, 25.1.1.2, or 25.1.3.x).
      owner: IT Operations
      addresses: CVE-2026-104935
      evidence: Vendor provided version update path
updates:
  - at: "2026-10-13T17:36:33Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-104935
  - at: "2026-10-23T19:50:41Z"
    level: L2
    summary: connect secure version <= 25.1.1.1, <= 25.1.2.2, <= 22.8R2.4
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ivanti-connect-secure-cve-2026-104935
---

Ivanti has disclosed a critical zero-day vulnerability, CVE-2026-104935, affecting Ivanti Connect Secure, a solution used to provide remote access to organizational systems and applications. The vulnerability allows an unauthenticated, remote attacker to execute arbitrary commands on the appliance without the need for valid credentials. Ivanti has assigned a CVSS score of 8.6 to this vulnerability. The Netherlands National Cyber Security Centre (NCSC) and Ivanti have confirmed that this vulnerability is being actively exploited by malicious actors in the wild to gain unauthorized access to target organizations. Due to the nature of the appliance providing network-level access, successful exploitation significantly compromises the security of downstream internal systems. Organizations are advised to verify their current version and apply security patches immediately. Because the vulnerability allows for persistent unauthorized control, patching alone is insufficient if the system has already been compromised; incident response procedures must be followed if intrusion is suspected.

## Impact

The vulnerability allows for full system control by unauthorized actors, potentially leading to widespread data exfiltration, lateral movement within the network, and the deployment of additional malicious tools. The vulnerability is being exploited in the wild against a limited number of customers. The NCSC classifies both the risk of exploitation and the potential damage as high.

## Recommendation

- Identify the current version of Ivanti Connect Secure and verify it against the patches listed by Ivanti.
- Apply the relevant security update immediately. For the 22.8 series, update to 22.8R2.5 or migrate to the 25.1 branch (25.1.1.2 or newer). For the 25.1 series, update to 25.1.1.2, 25.1.2.2 (if supported by migration path), or 25.1.3.0/25.1.3.1.
- Initiate incident response procedures if unauthorized access is suspected, as patching does not remediate established backdoors or persistence.
- Monitor logs for unusual authentication activity or unexpected process execution occurring on the Connect Secure appliance.
