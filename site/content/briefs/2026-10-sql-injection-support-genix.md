---
title: SQL Injection Vulnerability in Support Genix WordPress Plugin
slug: 2026-10-sql-injection-support-genix
description: An SQL injection vulnerability in the Support Genix WordPress plugin allows remote attackers to execute arbitrary database queries, potentially leading to full unauthorized data access or modification.
date: "2026-10-18T11:57:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:devitems:support_genix:*:*:*:*:*:wordpress:*:*
vendors:
  - DevItems
products:
  - Support Genix (<= 1.4.54)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The Support Genix plugin is a server-side component of the WordPress platform that is vulnerable to exploitation.
    confidence_band: high
cves:
  - id: CVE-2026-110895
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110895
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all WordPress instances to identify active Support Genix installations.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110895 affects Support Genix versions up to 1.4.54.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove the Support Genix plugin until a security update is confirmed.
      owner: IT Operations
      addresses: CVE-2026-110895
      evidence: Source identifies vulnerability in all versions through 1.4.54.
---

The Support Genix plugin for WordPress is affected by an SQL injection vulnerability, identified as CVE-2026-110895, due to the improper neutralization of special elements within SQL commands. This flaw exists in all versions of the Support Genix Lite plugin up to and including 1.4.54. The vulnerability is highly critical as it allows both authenticated and unauthenticated attackers to manipulate the plugin's database interactions. By injecting malicious SQL payloads, an adversary can bypass security controls to exfiltrate sensitive site data, modify database records, or potentially gain further control over the WordPress application environment. This vulnerability highlights the ongoing risk of insecure input handling in third-party WordPress plugins and mandates immediate remediation for any organization utilizing this software.

## Impact

Successful exploitation of this vulnerability enables attackers to perform unauthorized database operations on the affected WordPress site. This can lead to the complete compromise of data stored within the application, including user information, internal site configuration, and sensitive business records. If the database user has elevated privileges, the impact could potentially extend to full site compromise or lateral movement within the hosting infrastructure.

## Recommendation

- Immediately identify and audit all WordPress installations for the presence of the Support Genix plugin.
- Disable or uninstall the Support Genix plugin if an update to a version beyond 1.4.54 is not yet available or verified by the vendor.
- Review web server logs for suspicious POST or GET requests targeting the Support Genix plugin endpoints that contain SQL keywords (e.g., UNION, SELECT, OR 1=1) or common SQL injection syntax.
- Implement a Web Application Firewall (WAF) to block requests containing common SQL injection patterns targeting WordPress plugin parameters.
- Perform a security scan of the database for unauthorized user accounts or anomalous data changes following the discovery of this vulnerability.
