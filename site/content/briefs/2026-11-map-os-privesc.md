---
brief_id: brief-2026-11-10-map-os-privesc
event_id: brief-2026-11-10-map-os-privesc
revision: 1
activity_at: "2026-11-10T02:04:36Z"
title: 'Map-OS: Privilege escalation in REST users API (CVE-2026-125382)'
slug: 2026-11-map-os-privesc
description: Map-OS versions 5.0.0 through 5.2.1 contain a privilege escalation vulnerability in the REST API that allows low-privileged users to modify administrative account settings.
date: "2026-11-10T02:04:36Z"
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
cpes:
  - cpe:2.3:a:map-os:map-os:*:*:*:*:*:*:*:*
vendors:
  - Map-OS
products:
  - Map-OS (5.0.0 <= version < 5.2.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Map-OS 5.0.0 to before 5.2.2 contains a privilege escalation vulnerability in the REST users API that allows non-administrator operators holding the cUsuario permission to bypass permission-delegation and super-administrator protections.
    confidence_band: high
cves:
  - id: CVE-2026-125382
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125382
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Map-OS to version 5.2.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source advises patch to resolve CVE-2026-125382
  hunt_leads:
    - lead: Identify unauthorized account modifications or group changes in /api/v1/usuarios logs
      technique_id: T1068
      data_needed:
        - Web server access logs or application audit logs for /api/v1/usuarios
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can send POST, PUT, or DELETE requests to /api/v1/usuarios to assign the Administrador group
  mitigation_plan:
    - priority: immediate
      action: Upgrade Map-OS to 5.2.2
      owner: IT Operations
      addresses: CVE-2026-125382
      evidence: NVD source confirms vulnerability exists in versions < 5.2.2
---

Map-OS versions 5.0.0 through 5.2.1 contain a privilege escalation vulnerability in the REST users API. An attacker with 'cUsuario' permissions can bypass permission-delegation protections by sending unauthorized POST, PUT, or DELETE requests to the /api/v1/usuarios endpoint. Successful exploitation allows an attacker to assign themselves to the 'Administrador' group, reset the super administrator password, or delete other accounts.

## Impact

An authenticated non-administrator user can achieve full control over the Map-OS instance by modifying administrative account attributes or deleting high-privileged users.

## Recommendation

- Upgrade Map-OS to version 5.2.2 or later to patch CVE-2026-125382.
- Audit logs for the /api/v1/usuarios endpoint to identify suspicious modifications made by non-administrator accounts.
