---
title: Arbitrary Code Execution in GIMP via GIMPressionist Preset Files
slug: 2026-09-gimp-memory-corruption
description: A memory corruption vulnerability in GIMP allows attackers to achieve arbitrary code execution by tricking a user into opening a maliciously crafted GIMPressionist preset file.
date: "2026-09-24T10:46:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - cve-2026-97185
vendors:
  - GIMP
products:
  - GIMP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker could exploit this by convincing a user to load a malicious preset file, potentially causing a crash or enabling arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-97185
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97185
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Monitor security advisories from GIMP for the release of a patched version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-97185 advisory
  mitigation_plan:
    - priority: immediate
      action: Advise users to avoid loading GIMPressionist preset files from untrusted sources.
      owner: Security Operations
      addresses: CVE-2026-97185
      evidence: CVE-2026-97185 advisory
---

A memory corruption vulnerability (CVE-2026-97185) exists in the GIMPressionist plug-in within GIMP. The flaw occurs because the plug-in fails to properly validate vector indices before performing write operations into fixed-size arrays when parsing GIMPressionist preset files. An attacker can exploit this by crafting a malicious preset file that triggers an out-of-bounds write. If a user is convinced to load this specially crafted file into GIMP, the resulting memory corruption can lead to application crashes or allow for arbitrary code execution in the context of the user running the software. This vulnerability represents a significant risk for users who frequently import configuration or preset files from untrusted sources, as the exploitation is triggered through standard application functionality.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain code execution on the target system. This could lead to full system compromise, data theft, or the installation of persistent backdoors depending on the privileges of the user running GIMP. The attack surface includes any environment where GIMP is installed on Windows, Linux, or macOS systems.

## Recommendation

Detection and mitigation should focus on preventing the execution of GIMP with untrusted configuration files and monitoring for abnormal process behavior associated with GIMP.

- Update GIMP to the latest version once a patch is provided by the GIMP development team to resolve CVE-2026-97185.
- Implement application control policies to restrict the ability of users to load configuration files from non-standard or external locations.
- Monitor for GIMP process crashes or unexpected termination events which may indicate exploitation attempts.
