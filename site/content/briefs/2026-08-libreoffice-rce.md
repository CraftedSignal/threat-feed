---
title: Remote Code Execution Vulnerability in LibreOffice
slug: 2026-08-libreoffice-rce
description: A vulnerability in LibreOffice allows a remote, unauthenticated attacker to execute arbitrary code on the victim's system via maliciously crafted files.
date: "2026-08-25T09:59:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - The Document Foundation
products:
  - LibreOffice
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A vulnerability in LibreOffice allows a remote, unauthenticated attacker to execute arbitrary code on the victim's system.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0483
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update all LibreOffice installations to the latest version.
      owner: IT Operations
      due: 48h
      evidence: General security best practice for patching identified vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Disable automatic macro execution in office applications.
      owner: IT Operations
      addresses: Arbitrary code execution via document parsing
      evidence: Common mitigation for document-based RCE
---

The Document Foundation has identified a security vulnerability in LibreOffice that permits a remote, unauthenticated attacker to achieve arbitrary code execution. This vulnerability presents a significant risk to end-user systems, as successful exploitation could allow an attacker to execute malicious commands within the context of the current user. Users are urged to update to the latest available version of LibreOffice to mitigate this risk. Given the nature of office productivity suites, the primary vector likely involves the handling of specially crafted documents containing malicious macros or embedded objects designed to trigger memory corruption or logic flaws during the document parsing process.

## Impact

Successful exploitation of this vulnerability enables remote code execution on the target workstation or server. This could lead to full system compromise, unauthorized access to sensitive documents, or the installation of further payloads such as ransomware or data exfiltration tools. The impact is broad, affecting all users of the LibreOffice suite across Windows, Linux, and macOS platforms.

## Recommendation

- Update all installations of LibreOffice to the most recent version provided by The Document Foundation to resolve the vulnerability.
- Implement endpoint security policies that restrict the execution of untrusted or unsigned macros within office productivity software.
- Monitor endpoint process-creation logs for abnormal child processes spawned by soffice.exe or the equivalent process on Linux and macOS, such as cmd.exe, powershell.exe, or bash.
