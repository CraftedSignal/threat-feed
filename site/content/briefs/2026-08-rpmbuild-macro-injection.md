---
title: Macro Injection Vulnerability in rpmbuild (CVE-2026-78367)
slug: 2026-08-rpmbuild-macro-injection
description: A macro injection vulnerability in rpmbuild allows remote attackers to achieve arbitrary code execution by convincing a user to process a specially crafted tarball.
date: "2026-08-24T16:03:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - rpmbuild
  - rhel
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
  - Red Hat Hardened Images
affected_os:
  - RHEL 7
  - RHEL 8
  - RHEL 9
  - RHEL 10
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This vulnerability allows a remote attacker to execute arbitrary code on the system by convincing a user to build a malicious tarball.
    confidence_band: high
cves:
  - id: CVE-2026-78367
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78367
  - https://access.redhat.com/security/cve/CVE-2026-78367
  - https://bugzilla.redhat.com/show_bug.cgi?id=2521857
  - https://github.com/rpm-software-management/rpm/issues/4314
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Deploy security updates for rpm package once released by Red Hat
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-78367
  mitigation_plan:
    - priority: short_term
      action: Isolate build environments processing untrusted tarballs
      owner: Security Engineering
      addresses: CVE-2026-78367
      evidence: Source documentation on macro injection vector
---

CVE-2026-78367 is a macro injection vulnerability in `rpmbuild`, a utility commonly used within Red Hat Enterprise Linux (RHEL) environments to build RPM packages. When `rpmbuild` operates in tarball mode and processes a specially crafted tarball, an attacker can leverage malicious tar member names to trigger macro injection. Successful exploitation results in arbitrary code execution on the target system. 

The attack requires user interaction, specifically convincing a user to perform an `rpmbuild` operation on a malicious archive. Given that `rpmbuild` is frequently used by developers, build engineers, and system administrators, the impact is highest in environments where external or untrusted source tarballs are processed during CI/CD or package maintenance workflows. The vulnerability is tracked as CWE-74 (Improper Neutralization of Special Elements in Output Used by a Downstream Component).

## Impact

The vulnerability carries a CVSS 3.1 score of 7.0. If exploited, an attacker can gain the same level of access as the user running the `rpmbuild` command. This can lead to full system compromise, exfiltration of source code or environment credentials, and persistent backdooring of build environments. Targeted sectors include any organization relying on RHEL-based distributions for software development or infrastructure management.

## Recommendation

Prioritize patching systems where `rpmbuild` is active in automated build pipelines.
- Review and restrict the use of untrusted source tarballs in automated build environments.
- Apply security patches provided by Red Hat for RHEL 7, 8, 9, and 10 as soon as they are made available via official channels.
- Audit build logs for suspicious file names or macro characters within tarball member names.
