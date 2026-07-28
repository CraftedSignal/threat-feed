---
title: '@wakaru/cli Arbitrary File Write Vulnerability CVE-2026-54545'
slug: 2026-07-wakaru-cli-file-write
description: '@wakaru/cli versions from 1.0.0 up to, but not including, 1.4.0 are vulnerable to arbitrary file write due to a path traversal flaw when unpacking a crafted JavaScript bundle using the `--unpack` command, where specially formatted filenames can bypass sanitization and lead to remote code execution.'
date: "2026-07-28T14:45:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - path-traversal
  - code-execution
  - javascript
  - cli-tool
vendors:
  - Wakaru
products:
  - '@wakaru/cli (< 1.4.0)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Depending on the target path and user environment, this may lead to code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: A crafted filename containing overlapping path traversal characters, such as `....//`, could be transformed into `../` after sanitization. This allowed the final output path to escape the intended output directory.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-7wpj-vvmv-pgm8
---

A high-severity arbitrary file write vulnerability, tracked as CVE-2026-54545, has been identified in `@wakaru/cli` versions 1.0.0 through 1.3.x. This flaw allows an attacker to write files outside the intended output directory when a user unpacks a specially crafted JavaScript bundle using the `wakaru --unpack` command. The vulnerability stems from insufficient sanitization of bundle-controlled module filenames, where overlapping path traversal characters (e.g., `....//`) are mishandled, converting to `../` after sanitization. This bypass enables an attacker to escape the designated directory and write malicious files to arbitrary locations on the file system. Depending on the target path and user environment, successful exploitation could lead to code execution, compromising the affected system. Users are strongly advised to upgrade to version 1.4.0 or later to mitigate this risk.

## Attack Chain

1. An attacker crafts a malicious JavaScript bundle that includes specially formatted filenames containing overlapping path traversal characters, such as `....//`.
2. The attacker delivers this malicious bundle to a target user, potentially via phishing, untrusted repositories, or compromised distribution channels.
3. The attacker convinces the user to execute the `wakaru --unpack` command on the malicious bundle using an affected version of `@wakaru/cli`.
4. The `@wakaru/cli` application begins the process of unpacking the bundle and processing its module filenames.
5. During the internal sanitization process of bundle-controlled module filenames, the crafted `....//` sequence is improperly handled.
6. The sanitization logic inadvertently transforms `....//` into `../`, effectively creating an unintended path traversal.
7. As `wakaru` writes the extracted modules, the arbitrary `../` path component allows files to be written to locations outside the user's specified output directory.
8. Depending on the chosen target path, this arbitrary file write can be used to overwrite critical system files or place malicious executables, potentially leading to code execution.

## Impact

Successful exploitation of CVE-2026-54545 results in an arbitrary file write vulnerability. An attacker can place files anywhere on the target system where the user running `wakaru` has write permissions. This could lead to a range of severe consequences, including overwriting legitimate software, deploying persistent malware, or establishing unauthorized access. In many scenarios, an arbitrary file write is a critical precursor to remote code execution (RCE), allowing the attacker to fully compromise the system. The specific impact depends on the files written and their location, but the potential for complete system compromise is significant.

## Recommendation

* Upgrade `@wakaru/cli` to version `1.4.0` or later immediately to patch CVE-2026-54545.
* Avoid using the `wakaru --unpack` command on untrusted or unknown bundles if immediate upgrade is not possible.
* Implement strong application whitelisting policies to prevent the execution of unauthorized or newly written executables.
