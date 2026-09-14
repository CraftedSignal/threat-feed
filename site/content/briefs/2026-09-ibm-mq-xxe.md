---
title: IBM MQ XML External Entity Injection Vulnerability
slug: 2026-09-ibm-mq-xxe
description: An XML external entity injection vulnerability in IBM MQ allows authenticated attackers to perform arbitrary file reads or server-side request forgery during reply message processing.
date: "2026-09-14T21:36:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:mq:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - MQ (9.1.0.0 through 9.1.0.37 LTS, 9.2.0.0 through 9.2.0.43 LTS, 9.3.0.0 through 9.3.0.41 LTS, 9.3.0.0 through 9.3.5.1 CD, 9.4.0.0 through 9.4.0.25 LTS, 9.4.0.0 through 9.4.5.1 CD, 10.0.0.0 Managed File Transfer)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM MQ... could allow an authenticated attacker to read arbitrary files or perform server-side request forgery due to XML external entity injection in reply message processing.
    confidence_band: high
cves:
  - id: CVE-2026-13275
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13275
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable IBM MQ versions identified in CVE-2026-13275.
      owner: IT Operations
      due: 72h
      evidence: Source identifies CVE-2026-13275 as an XXE vulnerability requiring remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest non-vulnerable version of IBM MQ.
      owner: IT Operations
      addresses: CVE-2026-13275
      evidence: NVD vulnerability entry for CVE-2026-13275.
---

IBM MQ, a message-oriented middleware solution, contains a vulnerability identified as CVE-2026-13275 that stems from improper handling of XML input during reply message processing. This vulnerability enables an authenticated attacker to perform XML External Entity (XXE) injection attacks. By submitting specifically crafted XML messages, an attacker can coerce the IBM MQ application into reading arbitrary files from the host filesystem or performing unauthorized Server-Side Request Forgery (SSRF) requests to internal or external network resources. This flaw impacts multiple long-term support (LTS) and continuous delivery (CD) versions of IBM MQ, as well as the Managed File Transfer component. Given that IBM MQ often handles sensitive financial or operational data, successful exploitation could lead to the exposure of configuration files, credentials, or internal network mapping.

## Impact

The vulnerability allows authenticated attackers to bypass security boundaries within the messaging environment. Successful exploitation leads to unauthorized access to sensitive local files and the ability to conduct SSRF, potentially escalating access within the internal network. The scope covers a wide range of IBM MQ versions, impacting organizations relying on this middleware for enterprise application integration. If exploited, an attacker could exfiltrate configuration data or pivot to other internal services that are not directly exposed to the internet.

## Recommendation

Prioritized actions for security and IT teams:
* Patch IBM MQ installations to the latest version as recommended by IBM to remediate CVE-2026-13275.
* Audit IBM MQ message flow configurations to identify and restrict untrusted XML input sources.
* Monitor MQ audit logs for unusual file access patterns or connection attempts originating from the IBM MQ service account.
