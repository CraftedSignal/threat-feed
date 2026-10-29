---
brief_id: brief-2026-10-29-hashicorp-nomad-symlink
event_id: brief-2026-10-29-hashicorp-nomad-symlink
revision: 1
activity_at: "2026-10-29T20:40:31Z"
title: 'HashiCorp Nomad: Symlink following privilege escalation (CVE-2026-107347)'
slug: 2026-10-hashicorp-nomad-symlink
description: HashiCorp Nomad and Nomad Enterprise contain a symlink following vulnerability that allows malicious workloads to overwrite files outside of their allocation directory, potentially resulting in root-level code execution on the host.
date: "2026-10-29T20:40:31Z"
lastmod: "2026-10-29T20:40:58Z"
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
  - cpe:2.3:a:hashicorp:nomad:*:*:*:*:*:*:*:*
  - cpe:2.3:a:hashicorp:nomad_enterprise:*:*:*:*:*:*:*:*
vendors:
  - HashiCorp
products:
  - Nomad (< 2.1.0)
  - Nomad Enterprise (< 2.1.0, < 1.11.12, < 1.10.18)
  - Nomad Enterprise (< 1.10.18, 1.11.x < 1.11.12, 2.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: When the client agent runs as root, this could lead to code execution as root on the client host.
    confidence_band: high
cves:
  - id: CVE-2026-107347
    cvss: 8.4
    kev_status: "false"
  - id: CVE-2026-119168
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107347
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119168
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Patch Nomad to 2.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is fixed in Nomad 2.1.0 and Nomad Enterprise 2.1.0, 1.11.12, and 1.10.18.
    - action: Upgrade Nomad and Nomad Enterprise to version 2.1.0 or respective patched versions.
      owner: IT Operations
      due: 72h
      evidence: This vulnerability (CVE-2026-119168) is fixed in Nomad 2.1.0 and Nomad Enterprise 2.1.0, 1.11.12, and 1.10.18.
  hunt_leads:
    - lead: Identify Nomad jobs attempting to create or interact with symlinks within allocation directories.
      technique_id: T1068
      data_needed:
        - Host-level filesystem audit logs (e.g., auditd) or container runtime logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Malicious workload to modify files outside its allocation directory.
    - lead: Monitor host filesystem audit logs (e.g., auditd) for chown or chmod system calls initiated by nomad process or child processes within allocation directories.
      technique_id: T1068
      data_needed:
        - 'Linux auditd logs (syscall: chmod, fchmod, chown, fchown)'
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A malicious workload can exploit this to alter permissions and ownership of arbitrary host directories.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nomad to 2.1.0 or respective patched Enterprise versions.
      owner: IT Operations
      addresses: CVE-2026-107347
      evidence: Fixed in Nomad 2.1.0 and Nomad Enterprise 2.1.0, 1.11.12, and 1.10.18.
    - priority: immediate
      action: Apply security patches for CVE-2026-119168.
      owner: IT Operations
      addresses: CVE-2026-119168
      evidence: Vulnerability fixed in Nomad 2.1.0 and Nomad Enterprise versions 1.10.18, 1.11.12, and 2.1.0.
updates:
  - at: "2026-10-29T20:40:58Z"
    level: L2
    summary: added coverage for Nomad (< 2.1.0) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119168
---

HashiCorp Nomad and Nomad Enterprise are vulnerable to a symlink following issue during dispatch payload processing and executor log writes. An attacker with the ability to submit a job to the Nomad cluster can manipulate file paths via symlinks to escape the restricted allocation directory. If the Nomad client agent process is executing with root privileges, this vulnerability (CVE-2026-107347) facilitates local privilege escalation, allowing the attacker to write to sensitive system files and achieve arbitrary code execution.

## Impact

Successful exploitation allows a malicious workload to escape its container or allocation boundary and modify arbitrary files on the host filesystem. When the Nomad agent is configured with elevated permissions (root), this results in full host compromise.

## Recommendation

* Patch affected Nomad installations immediately. Update Nomad to version 2.1.0 or later.
* Update Nomad Enterprise instances to 2.1.0, 1.11.12, or 1.10.18.
* Audit Nomad client agent configuration to ensure the agent is not running as root unless strictly required.
* Review existing job specifications and submitted dispatch payloads for unauthorized path traversal or symlink usage.
