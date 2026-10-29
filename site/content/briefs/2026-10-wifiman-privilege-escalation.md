---
brief_id: brief-2026-10-29-wifiman-privilege-escalation
event_id: brief-2026-10-29-wifiman-privilege-escalation
revision: 1
activity_at: "2026-10-29T21:10:16Z"
title: 'Ubiquiti WiFiman Desktop: Local privilege escalation (CVE-2026-119250)'
slug: 2026-10-wifiman-privilege-escalation
description: A local, low-privileged user can exploit an External Control of File Name or Path vulnerability in Ubiquiti WiFiman Desktop for macOS to execute arbitrary commands as root.
date: "2026-10-29T21:10:16Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:ui:wifiman_desktop:*:*:*:*:*:macos:*:*
tags:
  - macos
  - privilege-escalation
  - vulnerability
vendors:
  - Ubiquiti
products:
  - WiFiman Desktop
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A malicious actor with local access and low privileges could exploit an External Control of File Name or Path vulnerability found in WiFiman Desktop for macOS to execute arbitrary commands with root privileges on the host device.
    confidence_band: high
cves:
  - id: CVE-2026-119250
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119250
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all macOS systems with WiFiman Desktop installed for risk assessment.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-119250 affects WiFiman Desktop for macOS.
  hunt_leads:
    - lead: Monitor for suspicious process execution where the parent is a WiFiman Desktop component but the child is an unexpected system utility or shell.
      technique_id: T1068
      data_needed:
        - Endpoint telemetry capturing parent-child process relationships
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows arbitrary command execution as root via the application.
  mitigation_plan:
    - priority: immediate
      action: Remove or isolate WiFiman Desktop on macOS endpoints until Ubiquiti releases a patch.
      owner: IT Operations
      addresses: CVE-2026-119250
      evidence: The vulnerability allows root privilege escalation.
---

Ubiquiti WiFiman Desktop for macOS contains an External Control of File Name or Path vulnerability (CVE-2026-119250). A local attacker with low-privileged access can exploit this flaw to execute arbitrary commands with root privileges. No specific public exploit code or patch status is detailed in the advisory beyond the existence of the vulnerability.

## Impact

Successful exploitation allows a local, unprivileged attacker to escalate their privileges to root on the affected macOS host, potentially leading to full system compromise.

## Recommendation

Inventory all macOS endpoints running WiFiman Desktop. Restrict local user access to the directory structures associated with the application, or uninstall the software until a security update is provided by the vendor.
