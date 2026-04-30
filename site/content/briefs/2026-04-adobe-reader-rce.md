---
title: Adobe Acrobat and Reader CVE-2026-34621 Zero-Day Exploitation
slug: 2026-04-adobe-reader-rce
description: Adobe patched CVE-2026-34621, a zero-day vulnerability in Acrobat and Reader exploited since December, allowing malicious PDFs to bypass sandboxes and execute arbitrary code, potentially leading to local file theft.
date: "2026-04-13T15:37:41Z"
severities:
  - critical
exploited: true
type: threat
types:
  - threat
tags:
  - adobe
  - acrobat
  - reader
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-34621
    cvss: 8.6
    epss: 0.07596
references:
  - https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/
iocs:
  - type: filename
    value: yummy_adobe_exploit_uwu.pdf
ioc_counts:
  filename: 1
rules:
  - title: Detect Execution of Suspicious JavaScript in PDFs
    description: Detects the execution of JavaScript within PDF files that may be indicative of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect PDF Opening with Suspicious Filename
    description: Detects the opening of a PDF file with a suspicious name, such as those used in exploit attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adobe has addressed CVE-2026-34621, a zero-day vulnerability affecting Acrobat DC, Acrobat Reader DC, and Acrobat 2024 versions on both Windows and macOS. This flaw has been actively exploited in the wild since at least December, with initial discovery occurring after a malicious PDF sample named "yummy_adobe_exploit_uwu.pdf" was submitted for analysis. The vulnerability allows specially crafted PDF files to bypass sandbox restrictions, invoke privileged JavaScript APIs, and potentially execute arbitrary code. Successful exploitation can lead to reading and stealing arbitrary local files. The impacted versions include Acrobat DC and Reader DC versions 26.001.21367 and earlier, as well as Acrobat 2024 versions 24.001.30356 and earlier. This zero-day requires immediate patching across enterprise and personal environments.

## Attack Chain

1.  Attacker crafts a malicious PDF file containing JavaScript code designed to exploit CVE-2026-34621.
2.  The attacker distributes the malicious PDF via email, web download, or other means.
3.  The victim opens the malicious PDF in a vulnerable version of Adobe Acrobat or Reader.
4.  The vulnerability allows the malicious PDF to bypass sandbox restrictions.
5.  The PDF invokes privileged JavaScript APIs, such as `util.readFileIntoStream()`, to read arbitrary local files.
6.  The PDF utilizes `RSS.addFeed()` to exfiltrate the stolen data to an attacker-controlled server.
7.  The attacker gains access to sensitive information stored on the victim's machine.
8.  The attacker uses the initial access for further exploitation, such as lateral movement or data exfiltration.

## Impact

Successful exploitation of CVE-2026-34621 allows attackers to bypass sandbox restrictions within Adobe Acrobat and Reader, leading to arbitrary code execution and unauthorized access to local files. This could result in the theft of sensitive data, such as credentials, financial information, or intellectual property. Although the number of victims is currently unknown, security researcher Gi7w0rm spotted attacks in the wild that leveraged Russian-language documents with oil and gas industry lures, and the potential impact is significant, especially for organizations that handle sensitive information in PDF documents.

## Recommendation

*   Immediately update Adobe Acrobat DC and Reader DC to version 26.001.21411 or later, and Acrobat 2024 to version 24.001.30362 (Windows) or 24.001.30360 (Mac) via 'Help > Check for Updates' to remediate CVE-2026-34621.
*   Implement the "Detect Execution of Suspicious JavaScript in PDFs" Sigma rule to identify potential exploitation attempts within your environment.
*   Monitor file creation events for files matching the name "yummy_adobe_exploit_uwu.pdf" or similar filenames identified during future investigations.
*   Educate users to be cautious when opening PDF files from untrusted sources and encourage them to verify the sender's authenticity before opening any attachments.
