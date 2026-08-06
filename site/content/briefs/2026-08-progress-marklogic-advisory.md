---
title: Critical Security Vulnerabilities in Progress MarkLogic Server
slug: 2026-08-progress-marklogic-advisory
description: Progress Software has released a security bulletin addressing ten critical vulnerabilities, including CVE-2026-7326 through CVE-2026-9203, affecting MarkLogic Server versions prior to 11.3.6 and 12.0.3.
date: "2026-08-06T21:26:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - security-advisory
  - patch-management
vendors:
  - Progress
products:
  - MarkLogic Server
cves:
  - id: CVE-2026-7557
    cvss: 9.1
  - id: CVE-2026-8709
    cvss: 9.9
  - id: CVE-2026-9190
    cvss: 9.1
  - id: CVE-2026-9192
    cvss: 9.8
  - id: CVE-2026-9193
    cvss: 9.9
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-security-advisory-av26-781
  - https://community.progress.com/s/article/Marklogic-Critical-Security-Alert-Bulletin-August-2026
  - https://www.progress.com/trust-center
iocs:
  - type: url
    value: https://community.progress.com/s/article/Marklogic-Critical-Security-Alert-Bulletin-August-2026
  - type: url
    value: https://www.progress.com/trust-center
ioc_counts:
  url: 2
---

Progress Software Corporation has issued a critical security advisory regarding multiple vulnerabilities identified in MarkLogic Server. The affected versions include all releases prior to 11.3.6 and 12.0.3. This bulletin addresses ten distinct CVEs: CVE-2026-7326, CVE-2026-7327, CVE-2026-7329, CVE-2026-7557, CVE-2026-8709, CVE-2026-9190, CVE-2026-9192, CVE-2026-9193, CVE-2026-9195, and CVE-2026-9203. The advisory provides critical patches to address security risks within the platform. Organizations currently utilizing these versions of MarkLogic Server are urged to review the official bulletin and prioritize patching to mitigate potential exploitation of these vulnerabilities.

## Impact

The identified vulnerabilities present a significant security risk to organizations hosting MarkLogic Server. Failure to apply the necessary security updates may leave systems susceptible to exploitation by unauthorized parties. The specific impact of these vulnerabilities varies depending on the nature of the security flaws described in the bulletin, but critical vulnerabilities often lead to unauthorized remote code execution, denial of service, or escalation of privileges within the enterprise environment.

## Recommendation

- Identify all instances of MarkLogic Server within the enterprise environment and verify if they are running versions below 11.3.6 or 12.0.3.
- Patch all affected MarkLogic Server instances to version 11.3.6, 12.0.3, or later as specified in the Progress Critical Security Alert Bulletin.
- Review the official Progress MarkLogic Critical Security Alert Bulletin for detailed technical mitigations related to CVE-2026-7326, CVE-2026-7327, CVE-2026-7329, CVE-2026-7557, CVE-2026-8709, CVE-2026-9190, CVE-2026-9192, CVE-2026-9193, CVE-2026-9195, and CVE-2026-9203.
