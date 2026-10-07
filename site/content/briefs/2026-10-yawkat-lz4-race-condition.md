---
title: Race Condition Vulnerability in lz4-java Native Library Extraction
slug: 2026-10-yawkat-lz4-race-condition
description: The lz4-java library is vulnerable to a race condition during native library extraction that allows a local user to perform arbitrary code execution or a denial of service.
date: "2026-10-07T22:48:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - local-exploitation
  - privilege-escalation
vendors:
  - yawkat
  - lz4
products:
  - lz4-java (<= 1.11.3)
  - lz4-java (>= 1.7.0, <= 1.8.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Another local user who can write to the same temporary directory can therefore create the file first and control the code that is loaded.
    confidence_band: high
cves:
  - id: CVE-2026-106451
references:
  - https://github.com/advisories/GHSA-mcr4-qmvw-px4g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106451
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade lz4-java dependency to 1.11.4 or higher
      owner: Development Team
      due: 48h
      evidence: Fixed in lz4-java 1.11.4
  mitigation_plan:
    - priority: immediate
      action: Set java.io.tmpdir to a private directory with restricted permissions
      owner: IT Operations
      addresses: CVE-2026-106451
      evidence: The workaround is to set java.io.tmpdir to a directory writable only by the application user
---

The yawkat and lz4 lz4-java libraries are vulnerable to a race condition in the `net.jpountz.util.Native.load()` method. When the library fails to find a system-installed native component, it extracts a bundled native JNI library to `java.io.tmpdir`. The library uses a predictable file path for the extraction, which is created using `FileOutputStream` without exclusive file creation flags. This allows a local attacker with write access to the same temporary directory to pre-create or symlink the file before the library extraction process completes.

If successful, the attacker can replace the intended native library with malicious code, which is then loaded by the victim's JVM via `System.load()`, executing with the victim's privileges. The vulnerability depends on host-level protections; systems with `fs.protected_regular` or `fs.protected_symlinks` enabled may mitigate the code execution vector but remain susceptible to a denial of service if the library fails to load. This vulnerability impacts lz4-java versions 1.7.0 through 1.8.1 and 1.11.3 and earlier.

## Impact

Successful exploitation allows a local attacker to execute arbitrary code within the context of the vulnerable Java application. In environments where OS-level protections (such as hardened symlink or file creation settings) are disabled, or in shared temporary directories without sticky bits (including certain container configurations), the risk of privilege escalation is significant. If exploitation is prevented by OS protections, attackers can still trigger a denial of service by causing the library loading process to fail, forcing the application to fall back to less performant Java implementations or crash.

## Recommendation

1. Patch immediately by upgrading to lz4-java version 1.11.4 or later, which utilizes secure temporary file creation.
2. For applications where patching is not immediately feasible, configure the application to run with a dedicated, private `java.io.tmpdir` that is restricted to the application service user.
3. Alternatively, install the native `liblz4-java` package at the OS level and ensure it is available on the `java.library.path`, which bypasses the insecure extraction logic entirely.
