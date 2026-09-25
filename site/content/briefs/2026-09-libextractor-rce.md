---
title: Arbitrary Code Execution in GNU libextractor via Environment Variable Injection
slug: 2026-09-libextractor-rce
description: GNU libextractor versions prior to 1.16 are vulnerable to arbitrary code execution due to the insecure handling of the LIBEXTRACTOR_PREFIX environment variable, which can be leveraged by local attackers for privilege escalation.
date: "2026-09-25T20:55:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnu:libextractor:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - vulnerability
vendors:
  - GNU
products:
  - libextractor (< 1.16)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: A local attacker can exploit this by setting LIBEXTRACTOR_PREFIX to a directory containing a malicious plugin that executes arbitrary code with elevated privileges when loaded by a setuid or setgid program.
    confidence_band: high
cves:
  - id: CVE-2026-100310
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100310
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade GNU libextractor to version 1.16 or later.
      owner: IT Operations
      addresses: CVE-2026-100310
      evidence: GNU libextractor before 1.16 loads plugins from an untrusted search path.
---

GNU libextractor before version 1.16 contains a vulnerability where the library fails to properly validate the LIBEXTRACTOR_PREFIX environment variable when searching for plugins. Because this variable influences the library's plugin loading path, a local attacker can set it to a directory they control. If a setuid or setgid binary utilizes libextractor, the library will load and execute malicious plugins located in the attacker-supplied directory with the privileges of the binary. This vulnerability allows an attacker to achieve privilege escalation on the host system. This is particularly critical in environments where setuid/setgid binaries are commonly used or where libextractor is embedded in privileged services.

## Impact

Successful exploitation of this vulnerability enables a local attacker to execute arbitrary code with elevated privileges. This could lead to a full system compromise, data theft, or persistence on the affected host. The scope is limited to systems where libextractor is utilized by setuid or setgid programs.

## Recommendation

- Upgrade libextractor to version 1.16 or later immediately to address the insecure environment variable handling.
- Audit existing setuid and setgid binaries on Linux systems to determine if they are linked against the affected libextractor library.
- Implement environment variable sanitization policies for high-privilege service accounts to prevent the injection of arbitrary paths into library search variables.
