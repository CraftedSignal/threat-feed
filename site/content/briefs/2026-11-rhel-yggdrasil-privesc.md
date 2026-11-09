---
brief_id: brief-2026-11-09-rhel-yggdrasil-privesc
event_id: brief-2026-11-09-rhel-yggdrasil-privesc
revision: 1
activity_at: "2026-11-09T16:06:29Z"
title: 'Red Hat Enterprise Linux: yggdrasil-worker-package-manager privilege escalation'
slug: 2026-11-rhel-yggdrasil-privesc
description: A vulnerability in the yggdrasil-worker-package-manager component of Red Hat Enterprise Linux allows a remote attacker to achieve privilege escalation, enabling unauthorized file creation, overwriting, or deletion with root privileges.
date: "2026-11-09T16:06:29Z"
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
  - cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux
affected_os:
  - RHEL
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter Angreifer kann eine Schwachstelle in Red Hat Enterprise Linux ausnutzen, um mit Root-Rechten Dateien zu erstellen, zu überschreiben oder zu löschen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4402
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory RHEL systems running the yggdrasil-worker-package-manager package
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects yggdrasil-worker-package-manager component
  hunt_leads:
    - lead: Monitor system logs and auditd for unexpected file creation or modification in protected system directories performed by the yggdrasil-worker-package-manager process.
      technique_id: T1068
      data_needed:
        - auditd logs
        - system integrity monitoring logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows creation, overwriting, or deletion of files with root privileges.
  mitigation_plan:
    - priority: immediate
      action: Apply relevant security patches from Red Hat as soon as released for the yggdrasil package.
      owner: IT Operations
      addresses: yggdrasil-worker-package-manager privilege escalation
      evidence: Source advises vulnerability in yggdrasil-worker-package-manager
---

A vulnerability has been identified in the yggdrasil-worker-package-manager component within Red Hat Enterprise Linux. This flaw permits a remote attacker to perform unauthorized file operations, including creation, overwriting, or deletion, while operating with root-level privileges. 

## Impact

The vulnerability results in unauthorized modification or deletion of files on the filesystem with the privileges of the root user, potentially leading to full system compromise or service disruption.

## Recommendation

* Identify all RHEL systems running the yggdrasil-worker-package-manager component.
* Monitor for security advisories from Red Hat regarding this component and apply the provided patches or configuration mitigations as soon as they become available.
* Implement file integrity monitoring (FIM) on critical system paths to detect unauthorized file creation or modification events by the yggdrasil worker process.
