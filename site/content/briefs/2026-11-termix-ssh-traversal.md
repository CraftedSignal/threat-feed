---
brief_id: brief-2026-11-02-termix-ssh-traversal
event_id: brief-2026-11-02-termix-ssh-traversal
revision: 1
activity_at: "2026-11-02T03:10:44Z"
title: 'Termix-SSH Termix: Path traversal in transferToHost (CVE-2026-120322)'
slug: 2026-11-termix-ssh-traversal
description: Termix-SSH Termix versions up to 2.9.2 are vulnerable to remote path traversal via the destPath argument in the /plugin-api/file-manager/transferToHost endpoint.
date: "2026-11-02T03:10:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:termix:termix-ssh_termix:*:*:*:*:*:*:*:*
tags:
  - webserver
  - path-traversal
  - cve
vendors:
  - Termix
products:
  - Termix-SSH Termix (<= 2.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument destPath leads to path traversal. The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-120322
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120322
rules:
  - title: Detects CVE-2026-120322 Exploitation - Path Traversal in transferToHost
    description: Detects attempts to exploit CVE-2026-120322 by looking for path traversal sequences in the destPath parameter of the transferToHost endpoint
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Termix-SSH Termix to core v26.10.0 and File Manager plugin v1.0.0
      owner: IT Operations
      due: 24h
      evidence: The shortcut was removed in the standalone File Manager plugin v1.0.0 and in core v26.10.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to /plugin-api/file-manager/transferToHost
      owner: IT Operations
      addresses: CVE-2026-120322
      evidence: The vulnerability is triggered by remote access to the transferToHost endpoint.
---

CVE-2026-120322 identifies a critical path traversal vulnerability in Termix-SSH Termix versions 2.9.2 and earlier. The flaw exists within the `/plugin-api/file-manager/transferToHost` endpoint, specifically in the processing of the `destPath` argument. Successful exploitation allows a remote attacker to manipulate file system operations. The vulnerability has been addressed by forcing file transfers to use SFTP in File Manager plugin v1.0.0 and core version v26.10.0.

## Impact

The vulnerability allows remote attackers to perform unauthorized file system operations. Publicly available exploit code exists, increasing the risk of active exploitation.

## Recommendation

* Immediately upgrade Termix-SSH Termix core to version v26.10.0 or higher.
* Upgrade the File Manager plugin to v1.0.0 or higher.
* If upgrading is not immediately possible, restrict network access to the `/plugin-api/file-manager/transferToHost` endpoint.
