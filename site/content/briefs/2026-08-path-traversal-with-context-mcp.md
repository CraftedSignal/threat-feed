---
title: Path Traversal Vulnerability in with-context-mcp
slug: 2026-08-path-traversal-with-context-mcp
description: A publicly disclosed path traversal vulnerability (CVE-2026-81491) in boxpositron with-context-mcp versions 3.0.7 and earlier allows remote attackers to manipulate file paths via specific ingested note functions.
date: "2026-08-27T05:33:59Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - path-traversal
  - vulnerability
  - remote-code-execution
vendors:
  - boxpositron
products:
  - with-context-mcp (<= 3.0.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-81491
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81491
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all systems running boxpositron with-context-mcp versions <= 3.0.7
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-81491 impacts these versions
  mitigation_plan:
    - priority: immediate
      action: Restrict remote access to affected applications via network-layer controls
      owner: IT Operations
      addresses: CVE-2026-81491
      evidence: Remote exploitation is possible
---

A path traversal vulnerability has been identified in the boxpositron with-context-mcp package, affecting versions up to 3.0.7. The flaw resides within the ingest_notes, teleport_notes, sync_notes, and project_folder functions located in src/index.ts. By supplying maliciously crafted inputs to these functions, a remote attacker can bypass intended file system restrictions to access or manipulate files outside of the application's designated scope. Publicly available exploit code exists for this vulnerability, and as of the reporting date, the maintainers have not issued a patch. This vulnerability poses a significant risk to systems utilizing this component for document or note processing, as it enables unauthorized file system operations.

## Impact

Successful exploitation of CVE-2026-81491 allows unauthenticated remote attackers to access unauthorized files on the underlying host system, potentially leading to the disclosure of sensitive information or the modification of configuration files. The lack of a patch means all deployments of the affected versions are currently vulnerable to exploitation.

## Recommendation

* Audit environments to identify all instances of the with-context-mcp package and confirm the installed version.
* Until an official patch is released by the maintainers, implement strict input validation for all data passed to the ingest_notes, teleport_notes, sync_notes, and project_folder functions to prevent directory traversal sequences (e.g., "../").
* Restrict access to services running with-context-mcp by placing them behind a WAF or VPN, limiting the potential for remote exploitation by unauthorized parties.
* Monitor file system logs for unexpected access patterns originating from the application user or service account.
