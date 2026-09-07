---
title: Authorization Bypass in sfturing hosp_order via userIdenf Parameter
slug: 2026-09-hosp-order-auth-bypass
description: An unpatched authorization bypass vulnerability in the sfturing hosp_order component allows remote attackers to manipulate the userIdenf parameter within OrderController.java to gain unauthorized access.
date: "2026-09-07T04:49:55Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:sfturing:hosp_order:*:*:*:*:*:*:*:*
vendors:
  - sfturing
products:
  - hosp_order (< 627f426331da8086ce8fff2017d65b1ddef384f8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The attack can be executed remotely.
    confidence_band: med
cves:
  - id: CVE-2026-86261
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86261
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to the hosp_order application.
      owner: IT Operations
      due: 24h
      evidence: Authorization bypass vulnerability allows remote exploitation.
  mitigation_plan:
    - priority: immediate
      action: Monitor project repository for patch releases covering CVE-2026-86261.
      owner: IT Operations
      addresses: CVE-2026-86261
      evidence: No current patch available.
---

A security vulnerability (CVE-2026-86261) has been identified in the sfturing hosp_order component, affecting versions up to the commit hash 627f426331da8086ce8fff2017d65b1ddef384f8. The flaw is located in the OrderController.java file, specifically within the Order Controller component. An attacker can perform a remote authorization bypass by manipulating the 'userIdenf' argument passed to the controller. This vulnerability allows for unauthorized access to hospital order data or functionality. 

The project uses a rolling release model, and no official fix is currently available as the maintainers have not yet responded to the reported issue. Public exploit code for this vulnerability is already available, increasing the risk of active exploitation. Defenders should restrict access to the affected web interface and monitor application logs for anomalous parameter manipulation.

## Impact

Successful exploitation of this vulnerability enables remote, unauthenticated actors to bypass authorization controls. This can result in unauthorized data access, modification, or operational disruption within the impacted hospital order system. Given the sensitive nature of the data likely handled by a product named 'hosp_order', this vulnerability poses a significant risk to data confidentiality and integrity.

## Recommendation

Prioritized actions for detection and mitigation:

- Restrict access to the impacted web application at the network perimeter (firewall/WAF) until a patch is released.
- Monitor web application access logs for unusually crafted values or atypical patterns in the 'userIdenf' query or request parameters.
- Monitor the project repository for updates and apply them immediately upon release once a fix for CVE-2026-86261 is integrated.
- Conduct an internal audit of all instances of hosp_order to identify and segment vulnerable deployments.
