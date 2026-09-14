---
title: Active Exploitation of Cisco Secure Email Gateway SQL Injection
slug: 2026-09-cisco-seg-sql-injection
description: CISA has added CVE-2026-76461 to the Known Exploited Vulnerabilities catalog, confirming active in-the-wild exploitation of a SQL injection vulnerability in Cisco Secure Email Gateway.
date: "2026-09-14T21:16:01Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:cisco:secure_email_gateway:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - sql-injection
  - cisa-kev
vendors:
  - Cisco
products:
  - Secure Email Gateway
cves:
  - id: CVE-2026-76461
    cvss: 9.8
references:
  - https://www.cisa.gov/news-events/alerts/2026/09/14/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-76461
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Cisco Secure Email Gateway to the latest version to mitigate CVE-2026-76461
      owner: IT Operations
      due: 24h
      evidence: CISA KEV Catalog requires rapid remediation of exploited vulnerabilities
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security patches to all internet-facing Cisco Secure Email Gateway appliances
      owner: IT Operations
      addresses: CVE-2026-76461
      evidence: CISA BOD 26-04 requirements for KEV catalog items
---

CISA has formally added CVE-2026-76461 to its Known Exploited Vulnerabilities (KEV) Catalog, signaling confirmed active exploitation of Cisco Secure Email Gateway appliances. This vulnerability is classified as a SQL injection flaw, allowing unauthenticated attackers to execute arbitrary SQL commands against the appliance's database backend. Given the critical position of the Secure Email Gateway in an organization's perimeter, successful exploitation grants threat actors potential administrative control, the ability to intercept email communications, and a foothold for lateral movement into the internal network. Organizations utilizing Cisco Secure Email Gateway must prioritize patching immediately, as this vulnerability is currently being leveraged by malicious actors.

## Impact

Successful exploitation of CVE-2026-76461 results in unauthorized access to the Cisco Secure Email Gateway, allowing attackers to bypass authentication controls, exfiltrate sensitive mail traffic, or modify appliance configurations. As this is a critical perimeter security component, compromise typically leads to total loss of confidentiality for organizational email and facilitates further network infiltration. The vulnerability poses a high risk to all enterprises that expose these management interfaces to the internet.

## Recommendation

Prioritize remediation of CVE-2026-76461 by applying the latest security patches provided by Cisco for the Secure Email Gateway. Conduct a forensic review of system logs to determine if the appliance was accessed or compromised prior to the application of security patches, as required by the guidance in BOD 26-04. Monitor the perimeter for abnormal SQL traffic patterns originating from or directed toward the email gateway management interfaces.
