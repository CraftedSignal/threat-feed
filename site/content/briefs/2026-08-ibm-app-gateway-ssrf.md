---
title: SSRF Vulnerability in IBM Application Gateway Operator
slug: 2026-08-ibm-app-gateway-ssrf
description: IBM Application Gateway Operator versions 22.2 through 26.06 contain a Server-Side Request Forgery vulnerability due to improper URL validation in custom resources, potentially allowing unauthorized access to internal resources.
date: "2026-08-05T17:20:44Z"
lastmod: "2026-08-10T19:30:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:application_gateway_operator:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - kubernetes
vendors:
  - IBM
products:
  - Application Gateway Operator (22.2 through 26.06)
  - Application Gateway Operator (<= 26.06)
  - Big SQL on IBM Cloud Pak for Data (7.7 on 5.0)
  - Big SQL on IBM Software Hub (multiple versions)
  - Business Automation Workflow (26.0.0, <= 24.0.0 IF009, <= 24.0.1 IF007, <= 25.0.0 IF005)
  - Cloud APM (<= 8.1.4)
  - Cloud Pak For Business Automation (24.0.0, 24.0.1, 25.0.0, 26.0.0)
  - IBM Event Streams (13.0.1)
  - Langflow OSS (<= 1.10.3)
  - Maximo Application Suite (9.0, 9.1, 9.2)
  - IBM Netezza Appliance (1.0.2.0)
  - Operational Decision Manager (multiple versions)
  - PowerVC (multiple versions)
  - Process Automation Manager Open Edition Starter Kit for Banking (<= 9.4.1)
  - SevOne Network Performance Management (<= 8.2.2)
  - QRadar (<= 7.5.0 UP 15 IF005, <= 7.6.0.1)
  - Security Verify Information Queue (multiple versions)
  - Storage Protect Operations Center (<= 8.1, <= 8.2)
  - webMethods Managed File Transfer (<= 11.1, <= 12.1)
  - WebSphere Application Server (8.5, 9.0)
  - WebSphere Application Server - Liberty (continuous delivery)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Application Gateway Operator 22.2 through 26.06 is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation of URLs specified in custom resources.
    confidence_band: high
cves:
  - id: CVE-2026-17617
    cvss: 8.5
    epss: 0.0029
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17617
  - https://www.ibm.com/support/pages/node/7282296
  - https://cyber.gc.ca/en/alerts-advisories/ibm-security-advisory-av26-789
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch IBM Application Gateway Operator to remediate CVE-2026-17617
      owner: IT Operations
      due: 72h
      evidence: IBM advisory node/7282296
  mitigation_plan:
    - priority: immediate
      action: Restrict Kubernetes RBAC permissions for Custom Resource modifications
      owner: IT Operations
      addresses: CVE-2026-17617
      evidence: NVD vulnerability description
updates:
  - at: "2026-08-10T19:30:44Z"
    level: L1
    summary: new product
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/ibm-security-advisory-av26-789
---

IBM Application Gateway Operator versions 22.2 through 26.06 are impacted by a Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-17617. The flaw originates from insufficient validation of URL parameters specified within Kubernetes custom resources processed by the operator. An authenticated user with low-level privileges can manipulate these resources to force the gateway to initiate requests to arbitrary internal or external endpoints. This could lead to sensitive information disclosure or unauthorized interactions with internal services reachable from the gateway's network context. Defenders should audit configurations for the Application Gateway Operator and ensure that only trusted users have the ability to apply custom resource modifications.

## Impact

Successful exploitation allows a low-privileged attacker to perform unauthorized SSRF attacks, leading to the potential discovery of internal network topology, access to metadata services, or interaction with internal APIs that are otherwise unreachable from the public internet. The vulnerability impacts all deployments of the IBM Application Gateway Operator between versions 22.2 and 26.06.

## Recommendation

* Prioritize patching to the latest version of IBM Application Gateway Operator as directed by the official IBM security advisory.
* Implement strict Role-Based Access Control (RBAC) within the Kubernetes cluster to limit the ability to create or modify custom resources associated with the Application Gateway Operator to only highly trusted service accounts or administrators.
* Review cluster network policies to restrict the egress capabilities of the IBM Application Gateway Operator pods, ensuring they can only communicate with required external or internal dependencies.
