---
brief_id: brief-2026-10-29-opnsense-rce
event_id: brief-2026-10-29-opnsense-rce
revision: 2
activity_at: "2026-10-30T13:30:40Z"
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
title: 'OPNsense: Remote authenticated arbitrary code execution'
slug: 2026-10-opnsense-rce
description: OPNsense contains a vulnerability that allows a remote, authenticated attacker to execute arbitrary code with administrator privileges.
date: "2026-10-29T12:14:17Z"
lastmod: "2026-10-30T13:29:11Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
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
vendors:
  - OPNsense
products:
  - OPNsense (< 26.7.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in OPNsense ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
cves:
  - id: CVE-2026-119409
    cvss: 7.2
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4201
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119409
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
  mitigation_plan:
    - priority: immediate
      action: Update OPNsense to 26.7.8 or later
      owner: IT Operations
      addresses: Arbitrary code execution vulnerability
      evidence: Source reports unpatched vulnerability
updates:
  - at: "2026-10-30T13:29:11Z"
    level: L2
    summary: added CVE-2026-119409; opnsense version < 26.7.8
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119409
---

A vulnerability in OPNsense allows a remote, authenticated attacker to achieve arbitrary code execution with administrator privileges. No CVE identifier is provided in the current BSI advisory. Users are advised to monitor the official OPNsense security announcements for patch availability and further technical details.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary code with administrative rights, potentially leading to full system compromise of the firewall appliance.

## Recommendation

Inventory all OPNsense instances within the environment. Monitor official OPNsense release channels for patches addressing this vulnerability and apply them immediately upon release. Audit administrative session logs for unauthorized access or suspicious command execution.
