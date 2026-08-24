---
title: Active Exploitation of Oracle HTTP Server and WebLogic Server Proxy Plug-in
slug: 2026-08-oracle-kev-addition
description: CISA has added CVE-2026-21962 to the Known Exploited Vulnerabilities (KEV) Catalog due to confirmed in-the-wild exploitation of an improper access control vulnerability in Oracle HTTP and WebLogic proxy components.
date: "2026-08-24T19:53:12Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:http_server:14.1.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:http_server:14.1.2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:12.2.1.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:14.1.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:weblogic_server_proxy_plug-in:14.1.2.0.0:*:*:*:*:*:*:*
vendors:
  - Oracle
products:
  - Oracle HTTP Server
  - Oracle Weblogic Server
cves:
  - id: CVE-2026-21962
    cvss: 10
    epss: 0.4323
references:
  - https://www.cisa.gov/news-events/alerts/2026/08/24/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-21962
  - https://edit.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Oracle HTTP Server and Oracle Weblogic Server for CVE-2026-21962
      owner: IT Operations
      due: 24h
      evidence: CISA KEV Catalog addition requirement per BOD 26-04
---

CISA has formally added CVE-2026-21962 to its Known Exploited Vulnerabilities (KEV) Catalog, citing active exploitation. The vulnerability affects Oracle HTTP Server and the Oracle WebLogic Server Proxy Plug-in. It is classified as an improper access control vulnerability. Successful exploitation of this vulnerability in proxy components can allow attackers to bypass security restrictions, potentially leading to unauthorized access to downstream application resources or total control of the affected asset. Given the critical position of proxy and load-balancing components in enterprise architectures, this vulnerability represents a significant risk for lateral movement and unauthorized information disclosure. Organizations are advised to prioritize patching according to Binding Operational Directive (BOD) 26-04 requirements.

## Impact

Successful exploitation allows unauthenticated or unauthorized attackers to manipulate requests passing through the Oracle HTTP Server or WebLogic Proxy Plug-in. This can lead to the exposure of sensitive back-end application data, session hijacking, or full remote code execution if combined with other backend weaknesses. The vulnerability is confirmed to be under active exploitation in the wild, necessitating immediate remediation on all internet-facing Oracle infrastructure.

## Recommendation

* Prioritize the application of security patches for CVE-2026-21962 on all internet-facing Oracle HTTP Server and Oracle WebLogic Server instances.
* Audit web access logs for anomalous request patterns targeting the WebLogic Proxy Plug-in (e.g., suspicious URI manipulation or unexpected headers).
* Enforce strict access control policies for the management interfaces of Oracle WebLogic environments.
* Conduct a review of system logs to determine if unauthorized access occurred prior to patch implementation, as outlined in the requirements of BOD 26-04.
