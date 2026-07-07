---
title: 'CVE-2025-71364: picklescan Remote Code Execution via Undetected asyncio._UnixSubprocessTransport._start'
slug: 2026-07-picklescan-rce
description: A remote code execution vulnerability (CVE-2025-71364) exists in picklescan versions prior to 0.0.30, allowing attackers to craft malicious Python pickle files embedding the `asyncio.unix_events._UnixSubprocessTransport._start` function that evade detection but execute arbitrary commands when loaded, leading to system compromise.
date: "2026-07-04T02:25:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - deserialization
  - python
  - picklescan
vendors:
  - picklescan
products:
  - picklescan < 0.0.30
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: picklescan before 0.0.30 fails to detect the asyncio.unix_events._UnixSubprocessTransport._start function in pickle reduce methods, allowing remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Attackers can craft malicious pickle files embedding this built-in function that evade detection but execute arbitrary commands when loaded.
    confidence_band: high
cves:
  - id: CVE-2025-71364
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71364
  - https://github.com/mmaitre314/picklescan/security/advisories/GHSA-q77w-mwjj-7mqx
  - https://www.vulncheck.com/advisories/picklescan-arbitrary-code-execution-via-undetected-asyncio-unix-events-unixsubprocesstransport-start
---

CVE-2025-71364 addresses a critical remote code execution (RCE) vulnerability in `picklescan` versions before 0.0.30. `picklescan` is a security tool designed to detect malicious constructs within Python pickle files. However, a flaw exists where it fails to properly identify the `asyncio.unix_events._UnixSubprocessTransport._start` function when embedded within pickle reduce methods. Threat actors can leverage this oversight to craft sophisticated malicious pickle files. These specially constructed files bypass `picklescan`'s detection mechanisms, enabling arbitrary command execution when a vulnerable application attempts to deserialize them on Unix-like operating systems. This vulnerability poses a significant risk to systems that process untrusted pickle files and rely on `picklescan` for protection, as it allows attackers to bypass security controls and gain full control over affected systems.

## Attack Chain

1.  An attacker crafts a Python pickle file containing a malicious payload designed for remote code execution.
2.  This payload specifically embeds the `asyncio.unix_events._UnixSubprocessTransport._start` function within the pickle's reduce methods to evade detection.
3.  The attacker distributes the malicious pickle file to a victim, potentially via untrusted sources like compromised repositories, email attachments, or malicious file uploads.
4.  The victim's system, which uses `picklescan` for security scanning, processes the file as part of its operations.
5.  Due to a flaw in `picklescan` versions before 0.0.30, the embedded malicious function goes undetected during the scan.
6.  When a vulnerable application on a Unix-like system attempts to deserialize (load) the malicious pickle file, the `_UnixSubprocessTransport._start` function is invoked.
7.  This invocation leads to the execution of arbitrary commands embedded in the pickle, achieving Remote Code Execution (RCE) on the victim's system.

## Impact

The successful exploitation of CVE-2025-71364 results in arbitrary code execution on the compromised system. This grants attackers full control, allowing them to install malware, exfiltrate sensitive data, modify system configurations, or establish persistence. The vulnerability, rated with a CVSS v3.1 base score of 8.1 (High), primarily affects organizations and individuals who process or deserialize untrusted Python pickle files on Unix-like systems, especially those relying on `picklescan` for pre-processing security checks.

## Recommendation

*   Immediately upgrade `picklescan` to version 0.0.30 or later to patch CVE-2025-71364.
*   Implement strict validation and sanitization for any external or untrusted Python pickle files processed by applications.
*   As a general security practice, avoid deserializing pickle files from untrusted sources, even with security scanners in place.
