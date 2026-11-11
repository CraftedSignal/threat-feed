---
brief_id: brief-2026-11-11-crun-privilege-escalation
event_id: brief-2026-11-11-crun-privilege-escalation
revision: 1
activity_at: "2026-11-11T15:56:57Z"
title: 'Red Hat Enterprise Linux (crun): Local privilege escalation vulnerability'
slug: 2026-11-crun-privilege-escalation
description: A local privilege escalation vulnerability in the crun OCI runtime within Red Hat Enterprise Linux allows a local attacker to execute arbitrary code with administrative privileges.
date: "2026-11-11T15:56:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Information is extracted directly from the provided advisory.
vendors:
  - Red Hat
products:
  - crun
affected_os:
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in Red Hat Enterprise Linux (crun) ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4490
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory systems running the crun OCI runtime to assess the potential attack surface.
      owner: IT Operations
      due: 48h
      evidence: Source identifies vulnerability in crun runtime.
  hunt_leads:
    - lead: Monitor system audit logs for unauthorized escalation attempts involving containers or process execution patterns originating from local user accounts.
      technique_id: T1068
      data_needed:
        - Linux Auditd
        - Container runtime logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows arbitrary code execution with administrative privileges locally.
---

A vulnerability exists in the crun OCI runtime component used within Red Hat Enterprise Linux. This flaw allows an authenticated local attacker to gain elevated privileges and execute arbitrary code as root. The technical details of the exploitation vector remain undisclosed by the source.

## Impact
Successful exploitation results in full administrative control over the affected system by an attacker who has already obtained local access.

## Recommendation
- Identify systems running the crun OCI runtime within the organization.
- Monitor vendor security advisories from Red Hat for package updates and security patches.
- Ensure strict access control policies for local system accounts to mitigate the impact of potential local privilege escalation vectors.
