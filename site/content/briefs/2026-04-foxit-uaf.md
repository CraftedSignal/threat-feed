---
title: Foxit Application Use-After-Free Vulnerability (CVE-2026-3779)
slug: 2026-04-foxit-uaf
description: CVE-2026-3779 is a use-after-free vulnerability in a Foxit application where stale references to page/form objects can lead to arbitrary code execution via crafted documents.
date: "2026-04-01T02:16:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-3779
  - use-after-free
  - code-execution
  - foxit
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-3779
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3779
  - https://www.foxit.com/support/security-bulletins.html
rules:
  - title: Suspicious Child Process of Foxit Application
    description: Detects suspicious child processes spawned by the Foxit application, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Foxit Application launching mshta.exe
    description: Detects mshta.exe being launched by a Foxit application, which is often a sign of exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-3779 is a use-after-free vulnerability affecting an unspecified Foxit application. The vulnerability stems from the application's list box calculate array logic, which improperly manages references to page or form objects. Specifically, when these objects are deleted or re-created, the calculation logic retains stale references. This flaw allows attackers to craft malicious documents that, upon calculation, trigger a use-after-free condition. Successful exploitation of this vulnerability could enable an attacker to execute arbitrary code within the context of the affected application. The vulnerability was reported on March 31, 2026 and poses a significant risk to users who handle untrusted documents with the vulnerable application.

## Attack Chain

1.  Attacker crafts a malicious document exploiting the list box calculation logic.
2.  The user opens the document in a vulnerable Foxit application.
3.  The application attempts to perform a list box calculation.
4.  The stale reference within the list box calculate array logic is triggered.
5.  The application attempts to access the deleted or re-created page/form object.
6.  A use-after-free condition occurs, potentially corrupting memory.
7.  The attacker leverages memory corruption to inject and execute arbitrary code.
8.  The attacker gains control of the affected system.

## Impact

Successful exploitation of CVE-2026-3779 can lead to arbitrary code execution on the victim's machine. The CVSS v3.1 score of 7.8 indicates a high severity. Exploitation requires user interaction (opening a malicious document), limiting the scope somewhat. However, targeted spearphishing campaigns could deliver such malicious documents, impacting organizations that rely on the vulnerable Foxit application for document handling. The consequences include potential data theft, system compromise, and further propagation of malicious activity within the network.

## Recommendation

*   Monitor process creations for unusual child processes spawned by the Foxit application, using the process creation rule provided below.
*   Apply the security updates released by Foxit as outlined in their security bulletin to remediate CVE-2026-3779 (https://www.foxit.com/support/security-bulletins.html).
*   Educate users about the risks of opening documents from untrusted sources to reduce the likelihood of initial access via social engineering (T1566).
