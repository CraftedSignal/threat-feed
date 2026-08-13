---
title: Command Injection Vulnerability in Siemens Siveillance Video
slug: 2026-08-siemens-siveillance
description: A critical OS command injection vulnerability (CVE-2026-3014) in Siemens Siveillance Video allows authenticated users with administrative permissions to achieve remote code execution in the context of the Management Server service.
date: "2026-08-13T16:52:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - ics
  - industrial-control-systems
vendors:
  - Siemens
products:
  - Siveillance Video
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability causes users with edit permissions to the Management Server to be able to execute arbitrary code in context of the Management Server Service.
    confidence_band: high
cves:
  - id: CVE-2026-3014
    cvss: 9.1
    epss: 0.00539
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-10
  - https://www.cve.org/CVERecord?id=CVE-2026-3014
  - https://support.industry.siemens.com/cs/ww/en/view/109827783/
  - https://support.industry.siemens.com/cs/ww/en/view/109976123/
  - https://support.industry.siemens.com/cs/ww/en/view/109988670/
---

Siemens Siveillance Video, which utilizes the Milestone XProtect Management Server API, contains a critical vulnerability (CVE-2026-3014) categorized as OS Command Injection (CWE-78). The flaw resides within the Management Server API and enables an authenticated user holding edit permissions to the management server to execute arbitrary operating system commands. Successful exploitation results in command execution in the context of the Management Server Service, potentially granting an attacker full control over the affected video management system. The vulnerability affects multiple versions, including Siveillance Video V2023 R3 (prior to 23.3.27), V2024 R1 (prior to 24.1.16), and V2025 (prior to 25.1.15). Siemens has released hotfix patches to address this issue. Organizations are advised to update to the latest provided versions immediately to mitigate risk.

## Impact

The vulnerability carries a CVSS base score of 9.1 and poses a significant risk to critical infrastructure sectors, including critical manufacturing, communications, and commercial facilities. If exploited, an attacker could gain persistent access to video management infrastructure, potentially leading to the surveillance system's compromise, disruption of video monitoring capabilities, or lateral movement into broader operational technology environments.

## Recommendation

- Patch affected Siemens Siveillance Video deployments by updating to the version specified in the vendor remediation links (V23.3 HotfixRev27, V24.1 HotfixRev16, or V25.1 HotfixRev15).
- Restrict network access to the Siveillance Video Management Server, ensuring it is isolated from the public internet and business networks.
- Audit administrative accounts for the Management Server and enforce the principle of least privilege, specifically restricting 'edit' permissions to authorized personnel only.
- Implement network segmentation to isolate control systems from less secure segments, limiting the impact of a potential compromise.
