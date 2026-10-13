---
title: Denial of Service Vulnerability in IBM Aspera Enterprise WebApps
slug: 2026-10-ibm-aspera-dos
description: IBM Aspera Enterprise WebApps versions 1.0.0 through 1.0.6 are vulnerable to a denial of service attack due to uncontrolled resource consumption, allowing remote unauthenticated attackers to disrupt service availability.
date: "2026-10-13T00:34:14Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ibm:aspera_enterprise_webapps:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
vendors:
  - IBM
products:
  - Aspera Enterprise WebApps (1.0.0-1.0.6)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: IBM Aspera Enterprise WebApps 1.0.0 through 1.0.6 could allow a remote attacker to cause a denial of service due to uncontrolled resource consumption.
    confidence_band: high
cves:
  - id: CVE-2026-75095
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75095
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all servers running IBM Aspera Enterprise WebApps.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75095 identifies vulnerable versions 1.0.0-1.0.6.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM Aspera Enterprise WebApps to the latest version as recommended by IBM.
      owner: IT Operations
      addresses: CVE-2026-75095
      evidence: NVD vulnerability disclosure.
---

IBM Aspera Enterprise WebApps versions 1.0.0 through 1.0.6 contain a critical vulnerability identified as CVE-2026-75095. This flaw stems from improper management of system resources, which can be triggered by a remote attacker. Successful exploitation of this vulnerability leads to an uncontrolled resource consumption condition, effectively resulting in a denial of service (DoS) for the affected application. Because the application processes requests from remote users, an attacker can leverage this flaw to intentionally exhaust server resources like CPU or memory, rendering the service unresponsive to legitimate traffic. Given that this is a publicly disclosed vulnerability affecting server-side enterprise software, organizations deploying these versions should prioritize identifying affected instances and scheduling the necessary vendor patches to prevent potential service disruption.

## Impact

The vulnerability poses a significant risk to organizations relying on IBM Aspera Enterprise WebApps for critical data transfer operations. A successful denial of service attack can lead to prolonged downtime, preventing business units from accessing or transferring files, and requiring manual intervention to restore service. The impact is primarily on operational availability rather than data integrity or confidentiality.

## Recommendation

Prioritize the identification of all IBM Aspera Enterprise WebApps instances within the environment. Consult official IBM security advisories for the availability of security patches and apply updates to versions beyond 1.0.6 immediately. In the interim, implement rate limiting on network edge devices or web application firewalls to mitigate the impact of high-volume resource consumption requests targeting the application.
