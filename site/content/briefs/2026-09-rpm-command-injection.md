---
title: Command Injection in RPM Package Manager
slug: 2026-09-rpm-command-injection
description: A command injection vulnerability (CVE-2026-95521) in the rpm package manager allows arbitrary command execution when processing maliciously crafted source RPM files containing %() macro constructs.
date: "2026-09-24T14:47:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rpm:rpm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - supply-chain
vendors:
  - RPM.org
products:
  - rpm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Installing or rebuilding a source RPM whose source or spec file basenames contain a %() macro construct causes rpm to execute an attacker-controlled shell command via popen().
    confidence_band: high
cves:
  - id: CVE-2026-95521
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95521
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems using rpm for package building.
      owner: IT Operations
      due: 48h
  mitigation_plan:
    - priority: immediate
      action: Monitor for patched versions of rpm from primary Linux distribution vendors.
      owner: IT Operations
      addresses: CVE-2026-95521
---

CVE-2026-95521 is a high-severity command injection vulnerability identified in the rpm package manager. The flaw arises from insecure handling of source RPM files during installation or rebuild operations. When rpm processes a source RPM where the source or spec file basenames contain a %() macro construct, the package manager improperly invokes popen() to relocate the source file list. This execution path results in the arbitrary execution of attacker-supplied shell commands under the context of the user running the command, which may include build agents, developers, or system administrators. Because this logic is triggered by standard package processing workflows, it poses a significant risk to CI/CD pipelines and environments that ingest untrusted or third-party source packages.

## Impact

Successful exploitation allows for arbitrary code execution on any system that processes a malicious .src.rpm file. The impact is significant for build infrastructure, development environments, and automated packaging systems, as an attacker can gain the privileges of the user running the rpm command to perform post-exploitation activities, such as credential theft or lateral movement within the build environment.

## Recommendation

- Identify all systems and CI/CD runners utilizing the rpm package manager for rebuilding or installing source packages.
- Prioritize patching the rpm package as soon as security updates are provided by the vendor.
- Implement strict verification controls for incoming .src.rpm files from untrusted third-party sources.
- Audit build logs for occurrences of unexpected subshell execution or shell metacharacters within filenames handled by rpm.
