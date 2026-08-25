---
title: Arbitrary File Write Vulnerability in sos clean
slug: 2026-08-sos-clean-traversal
description: A path traversal vulnerability in the sos clean utility allows local attackers to create or overwrite arbitrary system files during tar archive extraction with root privileges.
date: "2026-08-25T16:09:11Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - sos-report
products:
  - sos
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This enables the attacker to write files to arbitrary locations on the system with the privileges of the sos clean process, which often runs as root.
    confidence_band: high
cves:
  - id: CVE-2026-79655
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79655
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit systems for installed sos package versions.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-79655 impacts the sos utility.
  mitigation_plan:
    - priority: immediate
      action: Patch the sos package to the latest version provided by the distribution vendor.
      owner: IT Operations
      addresses: CVE-2026-79655
      evidence: NVD vulnerability entry
---

The sos package, commonly used on Linux systems for gathering diagnostic information, contains a security flaw in the 'sos clean' utility identified as CVE-2026-79655. This utility is designed to sanitize collected data but fails to properly validate symlink and hardlink targets when processing tar archives. A local attacker can craft a malicious archive that, when processed by the utility, triggers a path traversal condition. Because 'sos clean' is frequently executed with root privileges to access protected system files, successful exploitation allows the attacker to overwrite sensitive configuration files, binary executables, or system credentials. This flaw enables local privilege escalation and persistent code execution by allowing an attacker to place malicious files in locations such as /etc/ or /usr/bin/ at the discretion of the attacker.

## Impact

Successful exploitation results in full system compromise via local privilege escalation. Since the utility operates with elevated privileges, an attacker can modify critical system files, potentially leading to unauthorized access, installation of backdoors, or system instability. This affects all Linux distributions utilizing the sos package for diagnostic reporting and log collection.

## Recommendation

Prioritize the identification of systems running affected versions of the sos package. Apply available security patches from distribution maintainers immediately to remediate CVE-2026-79655. If patching is not immediately feasible, restrict the ability of unauthorized local users to execute the 'sos clean' utility on sensitive systems. Monitor system logs for unexpected file write operations occurring in critical system directories originating from the 'sos' process context.
