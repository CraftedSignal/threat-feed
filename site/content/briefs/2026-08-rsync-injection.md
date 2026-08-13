---
title: Multiple Command and Argument Injection Vulnerabilities in rsync
slug: 2026-08-rsync-injection
description: Versions of rsync prior to 3.5.0 contain multiple command and argument injection flaws that allow attackers to execute arbitrary code via malicious hostnames, environment variables, and shell command injections.
date: "2026-08-13T15:38:06Z"
lastmod: "2026-08-13T15:42:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - rsync
  - file-transfer
  - cve-2026-53793
  - denial-of-service
  - network
vendors:
  - Samba
products:
  - rsync
  - rsync (2.0.0-3.4.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: rsync before 3.5.0 contains multiple command and argument injection vulnerabilities that allow attackers to execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The vulnerability is triggered through several code paths, including the RSYNC_CONNECT_PROG environment variable, daemon hooks, the rsync-ssl wrapper, and remote-shell command newline injection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can exploit improper handling of the /./ notation or forge delta-basis transfers referencing xname paths that cross the /./ boundary to gain unauthorized read or write access to files outside the module's subtree.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The rsync daemon (versions 2.0.0 through 3.4.9) is vulnerable to a denial of service attack where an unauthenticated remote attacker can exhaust all available connection slots.
    confidence_band: high
cves:
  - id: CVE-2026-53790
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53790
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53793
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70464
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade rsync to 3.5.0 or later on all systems
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-53790 patch requirement
updates:
  - at: "2026-08-13T15:38:16Z"
    level: L2
    summary: added coverage for rsync
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-53793
  - at: "2026-08-13T15:42:02Z"
    level: L1
    summary: added coverage for rsync (2.0.0-3.4.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70464
---

The rsync utility, in versions prior to 3.5.0, is affected by multiple command and argument injection vulnerabilities. These flaws reside in several code paths including the RSYNC_CONNECT_PROG environment variable, daemon hooks, the rsync-ssl wrapper, and remote-shell command newline injection. The vulnerability stems from insufficient sanitization of user-supplied inputs, specifically hostnames and hostspecs passed to the utility. An attacker providing crafted input containing shell metacharacters or newline characters can achieve command injection, leading to execution of arbitrary code with the privileges of the user running the rsync process. This affects any system leveraging rsync for file synchronization or as a backend for transfer services. Defenders should prioritize updating rsync to version 3.5.0 or later to mitigate the risk of arbitrary command execution across Linux, macOS, and Windows environments.

## Impact

Successful exploitation allows for arbitrary command execution on systems where rsync is invoked with attacker-controlled inputs. This poses a significant risk to servers, build systems, and automated backup pipelines that rely on rsync for remote data synchronization. Unauthorized code execution can lead to full system compromise, data exfiltration, or lateral movement within the network.

## Recommendation

- Upgrade the rsync binary to version 3.5.0 or higher across all affected server and workstation environments to patch CVE-2026-53790.
- Implement strict input validation for any automated scripts, web interfaces, or command-line wrappers that pass user-supplied strings as hostnames or parameters to rsync.
- Audit environment variables, specifically RSYNC_CONNECT_PROG, in automated execution environments to ensure they are not influenced by untrusted input sources.
