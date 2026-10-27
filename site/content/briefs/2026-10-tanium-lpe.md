---
brief_id: brief-2026-10-27-tanium-lpe
event_id: brief-2026-10-27-tanium-lpe
revision: 1
activity_at: "2026-10-27T20:01:46Z"
title: 'Tanium End-User Notifications: Local privilege escalation (CVE-2026-108304)'
slug: 2026-10-tanium-lpe
description: Tanium addressed a local privilege escalation vulnerability in the End-User Notifications component that allows low-privileged users to elevate privileges on affected hosts.
date: "2026-10-27T20:01:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of installed Tanium component versions
cpes:
  - cpe:2.3:a:tanium:end-user_notifications:*:*:*:*:*:*:*:*
vendors:
  - Tanium
products:
  - End-User Notifications
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Tanium addressed a local privilege escalation vulnerability in End-User Notifications.
    confidence_band: high
cves:
  - id: CVE-2026-108304
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108304
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of Tanium End-User Notifications to the latest version.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-108304 requires remediation via official vendor update.
  hunt_leads:
    - lead: Monitor process creation events for the End-User Notifications service spawning unusual child processes.
      technique_id: T1068
      data_needed:
        - Process creation logs (Event ID 1 or equivalent)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Privilege escalation vulnerabilities in service components often involve anomalous process execution.
  mitigation_plan:
    - priority: immediate
      action: Apply Tanium security patches for CVE-2026-108304.
      owner: IT Operations
      addresses: CVE-2026-108304
      evidence: NVD security bulletin.
---

Tanium has released a patch for a local privilege escalation vulnerability (CVE-2026-108304) affecting the End-User Notifications component. This vulnerability allows an attacker who already possesses low-privileged access to a system to gain elevated privileges. Details regarding the specific exploit path or the vulnerable version range are currently limited.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.8, indicating the potential for successful exploitation to significantly increase a user's privilege level on the host system.

## Recommendation

- Inventory all systems running Tanium End-User Notifications to identify exposure.
- Apply the latest security updates provided by Tanium to address CVE-2026-108304 immediately.
- Monitor local system logs for unauthorized attempts to interact with Tanium service processes or modifications to component configuration files by non-administrator users.
