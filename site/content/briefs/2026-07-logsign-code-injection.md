---
title: Unauthenticated Remote Code Injection in Logsign SIEM
slug: 2026-07-logsign-code-injection
description: Logsign SIEM versions prior to 6.4.108 are vulnerable to a critical code injection flaw (CVE-2026-17561) that enables unauthenticated remote attackers to achieve arbitrary code execution.
date: "2026-07-31T13:38:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - rce
  - siem
  - vulnerability
vendors:
  - Innotim Software, Telecommunications and Consulting Trade Ltd. Co.
products:
  - Logsign SIEM
cves:
  - id: CVE-2026-17561
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17561
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0717
---

A critical code injection vulnerability (CVE-2026-17561) exists in Logsign SIEM versions earlier than 6.4.108. The vulnerability, classified as CWE-94: Improper Control of Generation of Code, allows an unauthenticated remote attacker to inject and execute arbitrary code on the affected appliance. This flaw stems from a lack of proper validation or sanitization during code generation processes within the SIEM architecture. 

Given the central role of a SIEM in an organization's security infrastructure, the ability for an attacker to gain unauthenticated remote code execution (RCE) represents a significant threat. Successful exploitation could lead to full system compromise, exfiltration of sensitive security logs, or the manipulation of security alerts to hide malicious activity within the target network.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, reflecting its critical severity. It requires no authentication and utilizes a low-complexity attack vector, making it an attractive target for external threat actors. Organizations using Logsign SIEM are at risk of complete platform takeover, potentially leading to unauthorized data access, lateral movement, or the permanent impairment of security monitoring capabilities.

## Recommendation

1. Upgrade Logsign SIEM to version 6.4.108 or higher immediately to remediate the vulnerability identified by CVE-2026-17561.
2. Restrict network access to the Logsign SIEM management interface to authorized administrative segments only, ensuring it is not exposed to the public internet.
3. Review audit logs for anomalous process creation, unexpected outbound network connections from the SIEM appliance, or unauthorized file modifications, which could indicate successful exploitation.
