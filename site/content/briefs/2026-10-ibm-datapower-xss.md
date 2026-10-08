---
title: Cross-Site Scripting Vulnerability in IBM DataPower Gateway
slug: 2026-10-ibm-datapower-xss
description: IBM DataPower Gateway versions 10.6.0.0 through 10.6.0.10 contain a reflected cross-site scripting (XSS) vulnerability allowing unauthenticated remote attackers to execute arbitrary JavaScript in the Web UI.
date: "2026-10-08T15:09:55Z"
lastmod: "2026-10-08T15:11:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:datapower_gateway:10.6.0.0:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - patch-management
vendors:
  - IBM
products:
  - DataPower Gateway (10.6.0.0-10.6.0.10)
  - DataPower Gateway (10.5.0.0-10.5.0.22, 10.6.0.0-10.6.0.10, 10.6.1-10.6.6, 11.0.0.0-11.0.0.2)
  - DataPower Gateway (11.0.0.0-11.0.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This vulnerability allows an unauthenticated user to embed arbitrary JavaScript code in the Web UI.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: IBM DataPower Gateway 11.0.0.0 through 11.0.0.2 could allow a remote attacker to cause a denial of service due to uncontrolled resource consumption.
    confidence_band: high
cves:
  - id: CVE-2026-14990
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14990
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14991
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16169
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade IBM DataPower Gateway to version > 10.6.0.10
      owner: IT Operations
      due: 48h
      evidence: Source identifies 10.6.0.0 through 10.6.0.10 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Restrict Web UI access via network ACLs
      owner: IT Operations
      addresses: CVE-2026-14990
      evidence: Vulnerability exists in the Web UI component
updates:
  - at: "2026-10-08T15:10:23Z"
    level: L2
    summary: added coverage for DataPower Gateway (10.5.0.0-10.5.0.22, 10.6.0.0-10.6.0.10, 10.6.1-10.6.6, 11.0.0.0-11.0.0.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14991
  - at: "2026-10-08T15:11:11Z"
    level: L1
    summary: added coverage for DataPower Gateway (11.0.0.0-11.0.0.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16169
---

IBM DataPower Gateway versions 10.6.0.0 through 10.6.0.10 are affected by a cross-site scripting (XSS) vulnerability within the product's Web UI. The vulnerability allows an unauthenticated remote attacker to inject malicious JavaScript code into the web interface. Because the gateway interface processes user input without sufficient sanitization, an attacker can execute code in the context of an authenticated user's session. This could result in unauthorized administrative actions, sensitive information disclosure, or credential theft by intercepting session tokens. This vulnerability is critical for organizations relying on the DataPower Gateway for API management and security, as a compromise of the administrative interface undermines the security posture of the protected backend services.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the session of an authenticated user, such as an administrator. Potential consequences include the exfiltration of session cookies, modification of gateway configurations, and unauthorized access to managed API traffic. All deployments of IBM DataPower Gateway 10.6.0.0 through 10.6.0.10 are at risk.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade all instances of IBM DataPower Gateway to a version beyond 10.6.0.10 immediately.
- Until patching is possible, restrict access to the DataPower Web UI management interface to trusted IP addresses using network-level access control lists (ACLs).
- Monitor administrative audit logs for unusual access patterns or modifications performed in the Web UI.
