---
title: Arbitrary Code Execution in openssl-encrypt via Symlink Following
slug: 2026-08-openssl-encrypt-symlink-vuln
description: The openssl-encrypt Python package before version 1.4.9 is vulnerable to a symlink-following flaw in its verify-usb functionality, allowing attackers with physical access to removable drives to achieve arbitrary code execution via crafted __pycache__ files.
date: "2026-08-27T19:11:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - code-execution
  - python
products:
  - openssl-encrypt
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The planted file is never enumerated, added_files stays 0, and verify-usb reports PASSED, resulting in code execution when the victim runs the portable install.
    confidence_band: high
cves:
  - id: CVE-2026-81690
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81690
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade openssl-encrypt package to version 1.4.9 or later on all systems.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 1.4.9 (affects both 1.4.x and 1.5.x lines).
  mitigation_plan:
    - priority: immediate
      action: Restrict USB access to authorized devices only.
      owner: IT Operations
      addresses: CVE-2026-81690
      evidence: An evil-maid attacker with physical access to the removable drive could replace a tool-tree directory with a symlink.
---

The openssl-encrypt Python package (versions prior to 1.4.9) contains a critical symlink-following vulnerability in its verify-usb utility. The flaw arises from inconsistent handling of symbolic links during the directory scan process compared to the file verification stage. Specifically, the utility uses rglob() to enumerate drive contents, which treats symlinks as standard directories. Meanwhile, the verification logic uses O_NOFOLLOW, which only protects the final path component.

An attacker with physical access to a removable media device can exploit this by replacing a legitimate tool-tree directory with a symlink pointing to an attacker-controlled directory. This malicious copy contains identical files alongside a crafted .pyc file located in a __pycache__ folder. CPython prioritizes loading these byte-identical .pyc files over recompilation. Because the scan fails to enumerate the malicious files within the symlinked structure, the verification tool reports a PASSED status, tricking the victim into executing the untrusted portable install.

## Impact

Successful exploitation results in arbitrary code execution on the victim's host system when the portable software is launched. This primarily impacts users relying on the openssl-encrypt package for verifying integrity of removable media. The vulnerability affects both the 1.4.x and 1.5.x branches of the software.

## Recommendation

- Upgrade the openssl-encrypt package to version 1.4.9 or later immediately to patch the symlink handling flaw.
- Implement strict removable media usage policies to prevent unauthorized physical access to devices used with high-integrity verification tools.
- Audit logs for instances of verify-usb tool usage and ensure the software binary paths remain within expected, read-only directories on the host, rather than relying solely on the portable media's internal check.
