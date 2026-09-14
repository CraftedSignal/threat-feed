---
title: HAProxy Security Bypass Vulnerability
slug: 2026-09-haproxy-bypass
description: A vulnerability in HAProxy (CVE-2023-45538) allows remote, unauthenticated attackers to bypass security restrictions, manipulate data, and trigger denial-of-service conditions.
date: "2026-09-14T13:04:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - security-bypass
  - denial-of-service
  - network-security
vendors:
  - HAProxy
products:
  - HAProxy
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker can exploit the vulnerability to trigger a denial-of-service condition.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3323
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Identify vulnerable HAProxy instances and patch to the latest security version as specified by vendor advisories.
      owner: IT Operations
      addresses: CVE-2023-45538
      evidence: Vulnerability reported by BSI for HAProxy
---

The BSI has reported a vulnerability in HAProxy identified as CVE-2023-45538. This security flaw enables a remote, unauthenticated attacker to circumvent established security controls within the load balancer. By exploiting this issue, unauthorized actors may be able to perform unauthorized data manipulation or disrupt service availability, resulting in a Denial-of-Service (DoS) state. Given HAProxy's position as a critical infrastructure component for traffic routing and load balancing, the potential for unauthorized data inspection or traffic redirection is significant. Organizations utilizing HAProxy are advised to review the vulnerability documentation to determine the specific impact on their configuration and to apply relevant vendor patches as soon as they are made available to mitigate the risk of remote service disruption or unauthorized traffic handling.

## Impact

The vulnerability poses a risk of service interruption and data integrity compromise for any organization utilizing HAProxy in an internet-facing capacity. Successful exploitation can lead to a Denial-of-Service, impacting the availability of web applications and services relying on HAProxy for load balancing. Furthermore, the bypass of security restrictions may allow attackers to manipulate traffic streams, potentially leading to unauthorized access to downstream systems or data exfiltration.

## Recommendation

1. Identify all HAProxy instances within the environment using asset management tools or network discovery.
2. Consult the official HAProxy security documentation regarding CVE-2023-45538 to identify affected versions and verify if current configurations are susceptible.
3. Apply vendor-provided security patches immediately once available to remediate the vulnerability.
4. Implement strict access control lists (ACLs) to limit management and configuration interfaces to trusted administrative networks.
