---
title: IBM WebSphere Application Server Denial of Service Vulnerability
slug: 2026-10-ibm-websphere-dos
description: IBM WebSphere Application Server and Liberty are susceptible to an unauthenticated remote denial-of-service attack via CVE-2026-103499, which permits uncontrolled resource consumption.
date: "2026-10-13T14:37:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ibm:websphere_application_server:8.5:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:websphere_application_server:9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:websphere_application_server_liberty:17.0.0.3:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:websphere_application_server_liberty:26.0.0.10:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-server
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty (17.0.0.3 through 26.0.0.10)
  - WebSphere Application Server (8.5)
  - WebSphere Application Server (9.0)
cves:
  - id: CVE-2026-103499
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103499
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory systems running identified versions of WebSphere Application Server
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-103499 affects versions 8.5, 9.0, and Liberty 17.0.0.3-26.0.0.10
  mitigation_plan:
    - priority: immediate
      action: Patch IBM WebSphere Application Server to the version recommended by the vendor for CVE-2026-103499
      owner: IT Operations
      addresses: CVE-2026-103499
      evidence: Source documentation for CVE-2026-103499
---

IBM has identified a critical vulnerability, tracked as CVE-2026-103499, affecting multiple versions of the WebSphere Application Server and Liberty profile. The vulnerability arises from improper handling of resource management, specifically an uncontrolled resource consumption flaw. A remote, unauthenticated attacker can exploit this condition by sending specially crafted requests to the application server, leading to resource exhaustion. This impact effectively renders the service unresponsive to legitimate users, resulting in a denial-of-service (DoS) condition. The affected versions include Liberty 17.0.0.3 through 26.0.0.10, as well as IBM WebSphere Application Server versions 8.5 and 9.0. Defenders should prioritize identifying instances of these specific versions within their environment to mitigate the risk of service disruption.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service, leading to the exhaustion of server resources such as CPU or memory. This impacts the availability of business-critical applications hosted on the affected IBM WebSphere platforms. Organizations utilizing these versions face the risk of service downtime and operational disruption from remote, unauthenticated threat actors.

## Recommendation

* Review the server versions in use to identify instances matching Liberty 17.0.0.3 through 26.0.0.10, or WebSphere Application Server 8.5 and 9.0.
* Apply the official security patches provided by IBM for CVE-2026-103499 as soon as they are made available to remediate the resource consumption flaw.
* Monitor webserver logs for spikes in request volume or abnormal request patterns targeted at the application server that may indicate exploitation attempts.
