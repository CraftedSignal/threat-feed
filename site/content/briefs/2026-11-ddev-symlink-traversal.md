---
brief_id: brief-2026-11-10-ddev-symlink-traversal
event_id: brief-2026-11-10-ddev-symlink-traversal
revision: 1
activity_at: "2026-11-10T16:37:50Z"
title: 'DDEV: Incomplete symlink traversal fix allows arbitrary host file overwrite (CVE-2026-108262)'
slug: 2026-11-ddev-symlink-traversal
description: An incomplete fix for CVE-2026-32885 in DDEV allows attackers to perform arbitrary host file overwrites and achieve code execution by planting absolute symlinks via maliciously crafted tar archives.
date: "2026-11-10T16:37:50Z"
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
  - cpe:2.3:a:ddev:ddev:*:*:*:*:*:*:*:*
vendors:
  - DDEV
products:
  - ddev (< 1.25.4)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.001
    technique_name: Change Default File Association
    evidence: Overwriting a shell rc-file, git hook, or cron entry yields code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: Malicious File
    evidence: Reachable via ddev add-on get <repo|url> (the exact remote-add-on vector the advisory names), and via ddev import-db / import-files.
    confidence_band: high
cves:
  - id: CVE-2026-108262
    cvss: 6.5
    epss: 0.00306
    kev_status: "false"
  - id: CVE-2026-32885
    cvss: 6.5
    epss: 0.00418
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-9hq4-hm3j-jmph
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade DDEV to 1.25.4 on all developer workstations and build servers.
      owner: IT Operations
      due: 24h
      evidence: DDEV versions prior to 1.25.4 are vulnerable.
  hunt_leads:
    - lead: Hunt for DDEV processes spawning child processes that perform writes to dot-files in home directories.
      technique_id: T1546.001
      data_needed:
        - Process creation logs (ParentImage, Image, CommandLine, TargetFileName)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit uses absolute symlinks to overwrite shell rc-files.
  mitigation_plan:
    - priority: immediate
      action: Upgrade DDEV to 1.25.4.
      owner: IT Operations
      addresses: CVE-2026-108262
      evidence: Vulnerability fixed in 1.25.4.
---

DDEV versions prior to 1.25.4 contain an incomplete fix for symlink traversal vulnerabilities. The application performs lexical validation on absolute symlink targets by rebasing them within a destination directory, but subsequently writes the raw, absolute target to the filesystem using `os.Symlink`. This discrepancy allows an attacker to plant a symlink pointing to an arbitrary host location. A subsequent file entry in the same archive can then traverse this symlink to overwrite sensitive files outside the intended extraction path. Successful exploitation targeting shell rc-files, git hooks, or cron jobs can result in arbitrary code execution. This vulnerability is reachable via `ddev add-on get`, `ddev import-db`, and `ddev import-files`.

## Attack Chain
1. Attacker crafts a malicious tar archive containing an absolute symlink entry (e.g., pointing to `/home/user/.zshrc`).
2. Attacker includes a second regular-file entry in the archive with a path that traverses the planted symlink.
3. DDEV `Untar` function processes the symlink; the lexical check passes because it rebases the path, but the file is created with the raw absolute target.
4. The malicious symlink is created on the host filesystem pointing to a sensitive file.
5. DDEV `Untar` processes the subsequent file entry, which passes the lexical check as it appears to be inside the destination.
6. `os.Create` follows the symlink and overwrites the target sensitive file on the host.

## Impact
Exploitation results in the ability to overwrite arbitrary files on the host filesystem with the privileges of the user running DDEV. By targeting shell configuration files, git hooks, or automation scripts, an attacker can achieve persistent code execution on the host machine.

## Recommendation
- Upgrade DDEV to version 1.25.4 or later immediately.
- Until patched, avoid executing `ddev` commands against untrusted or externally sourced archives, repositories, or add-ons.
- Implement file integrity monitoring on sensitive user directories (e.g., `$HOME/.ssh`, `$HOME/.zshrc`, `$HOME/.bashrc`, `git` hooks) to detect unauthorized file modifications occurring during DDEV operations.
