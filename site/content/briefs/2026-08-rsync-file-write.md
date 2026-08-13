---
title: Arbitrary File Write Vulnerability in rsync
slug: 2026-08-rsync-file-write
description: Rsync versions prior to 3.5.0 contain an arbitrary file write vulnerability that allows attackers to bypass path confinement by providing absolute paths to specific command-line options.
date: "2026-08-13T15:38:24Z"
lastmod: "2026-08-13T15:39:26Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - RsyncProject
products:
  - rsync
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rename-confinement logic is bypassed when these options resolve to paths outside the destination tree, enabling attacker-controlled values to write files to arbitrary locations accessible to the rsync process.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A sender can exploit the quadratic-time worst-case behavior in hash lookups to exhaust receiver CPU resources with a modest number of crafted entries, causing a sustained denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-53795
    cvss: 8.1
references:
  - https://github.com/RsyncProject/rsync/security/advisories/GHSA-m9vj-637x-v6pq
  - https://www.vulncheck.com/advisories/rsync-arbitrary-file-write-via-temp-dir-link-dest
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53795
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70453
  - https://github.com/RsyncProject/rsync/security/advisories/GHSA-8x5r-mjx8-83hv
  - https://www.vulncheck.com/advisories/rsync-algorithmic-complexity-dos-via-hash-search
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch rsync to 3.5.0 on all internet-facing or multi-user systems.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-53795 remediation requires upgrade to 3.5.0.
  mitigation_plan:
    - priority: immediate
      action: Identify and audit scripts using rsync --temp-dir or --link-dest flags.
      owner: Security Operations
      addresses: CVE-2026-53795
      evidence: Vulnerability relies on user-supplied input to these specific flags.
updates:
  - at: "2026-08-13T15:39:26Z"
    level: L1
    summary: added coverage for rsync
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70453
---

Rsync versions prior to 3.5.0 are vulnerable to an arbitrary file write vulnerability (CVE-2026-53795) caused by improper handling of absolute paths. When an attacker provides absolute paths via the --temp-dir or --link-dest command-line options, the application fails to correctly apply rename-confinement logic. This failure permits the rsync process to write files to locations outside the intended destination directory, provided those locations are writable by the user executing the rsync process. This vulnerability poses a significant risk to systems that process untrusted rsync inputs or automated synchronization tasks, as it could be leveraged to overwrite sensitive configuration files or inject malicious binaries, potentially leading to privilege escalation or system compromise.

## Attack Chain

1. Attacker identifies an automated system or user process executing rsync with user-controllable arguments.
2. Attacker crafts a malicious rsync command that includes the --temp-dir or --link-dest options.
3. Attacker specifies an absolute path for these options that targets a directory outside the intended scope.
4. The rsync process initiates, processing the supplied malicious path parameters.
5. The application fails to validate the absolute path against the destination tree restrictions.
6. The rename-confinement check is bypassed due to logic flaws in path resolution.
7. The rsync process writes a file to the attacker-defined absolute path location.
8. The attacker achieves unauthorized file creation or modification on the target system.

## Impact

Successful exploitation allows for the unauthorized creation or modification of files anywhere on the local filesystem that the rsync process has permissions to access. This can result in system instability, the injection of malicious scripts into cron jobs, or the overwriting of SSH authorized_keys, ultimately leading to full system compromise or persistence for the attacker.

## Recommendation

* Update rsync to version 3.5.0 or later on all systems to remediate CVE-2026-53795.
* Audit scripts and automation pipelines for rsync commands that utilize --temp-dir or --link-dest flags with untrusted input.
* Restrict the permissions of the user accounts executing rsync to the minimum necessary directory access to limit the potential impact of an arbitrary file write.
