---
brief_id: brief-2026-10-29-opnsense-rce
event_id: brief-2026-10-29-opnsense-rce
revision: 3
activity_at: "2026-11-03T20:05:20Z"
revision_history:
  - revision: 2
    at: "2026-10-30T13:30:40Z"
    checksum: sha256:07f8a243fff478f62fbef823541805a39c63794ea9bc9bd85d0d9ea8536af100
    summary: added CVE-2026-119409; opnsense version < 26.7.8
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119409
  - revision: 3
    at: "2026-11-03T20:05:20Z"
    checksum: sha256:755e7fdb177975fbee98246eb20a878e5e48430f26f0c55aed6092f1b5113487
    summary: added coverage for OPNsense (< 26.1.11, < 26.4.1p1)
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57154
title: 'OPNsense: Remote authenticated arbitrary code execution'
slug: 2026-10-opnsense-rce
description: OPNsense contains a vulnerability that allows a remote, authenticated attacker to execute arbitrary code with administrator privileges.
date: "2026-10-29T12:14:17Z"
lastmod: "2026-11-03T20:04:34Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: awaiting_vendor_patch_details
cpes:
  - cpe:2.3:a:opnsense:opnsense:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-security
  - privilege-escalation
  - web-application
  - injection
vendors:
  - OPNsense
products:
  - OPNsense (< 26.7.8)
  - OPNsense (< 26.1.11, < 26.4.1p1)
affected_os:
  - FreeBSD
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in OPNsense ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Line injection through Monit mail password and adjacent Monit text fields into /usr/local/etc/monitrc demonstrated root command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Line injection through Monit mail password and adjacent Monit text fields into /usr/local/etc/monitrc demonstrated root command execution.
    confidence_band: high
cves:
  - id: CVE-2026-119409
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-57154
    cvss: 8.1
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4201
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119409
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57154
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch OPNsense to 26.7.8 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms OPNsense vulnerability allowing arbitrary code execution
    - action: Patch OPNsense to version 26.1.11 or 26.4.1p1
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in versions 26.1.11 and 26.4.1p1.
  hunt_leads:
    - lead: Search administrative session logs for anomalous system commands or modifications to firewall rules and services
      technique_id: T1059
      data_needed:
        - OPNsense system audit logs
        - web interface access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows remote execution of arbitrary code via authenticated sessions
    - lead: Identify unauthorized modifications to OPNsense configuration files
      technique_id: T1068
      data_needed:
        - File integrity logs or system audit trails for /usr/local/etc/
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Applying or restarting the affected service can alter behavior beyond the delegated setting, create service-side files, cross RBAC boundaries, or cause denial of service.
  mitigation_plan:
    - priority: immediate
      action: Update OPNsense to 26.7.8 or later
      owner: IT Operations
      addresses: Arbitrary code execution vulnerability
      evidence: Source reports unpatched vulnerability
    - priority: immediate
      action: Restrict UI/API access for service configuration fields
      owner: SOC
      addresses: CVE-2026-57154
      evidence: Prior to 26.1.11 and 26.4.1p1, authenticated Web UI or API users with delegated access to affected settings can submit CR or LF characters
updates:
  - at: "2026-10-30T13:29:11Z"
    level: L2
    summary: added CVE-2026-119409;
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119409
  - at: "2026-11-03T20:04:34Z"
    level: L2
    summary: added coverage for OPNsense (< 26.1.11, < 26.4.1p1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57154
---

A vulnerability in OPNsense allows a remote, authenticated attacker to achieve arbitrary code execution with administrator privileges. No CVE identifier is provided in the current BSI advisory. Users are advised to monitor the official OPNsense security announcements for patch availability and further technical details.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary code with administrative rights, potentially leading to full system compromise of the firewall appliance.

## Recommendation

Inventory all OPNsense instances within the environment. Monitor official OPNsense release channels for patches addressing this vulnerability and apply them immediately upon release. Audit administrative session logs for unauthorized access or suspicious command execution.
