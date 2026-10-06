---
title: Unauthenticated Servlet Access Vulnerabilities in Hitachi Energy Asset Suite
slug: 2026-10-hitachi-asset-suite
description: Hitachi Energy Asset Suite versions 9.9.0 and prior are susceptible to unauthenticated access to sensitive servlets, enabling unauthorized configuration file uploads and denial-of-service conditions.
date: "2026-10-06T17:11:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hitachienergy:asset_suite:*:*:*:*:*:*:*:*
tags:
  - energy
  - ics
  - cve
  - vulnerability
vendors:
  - Hitachi Energy
products:
  - Asset Suite (<= 9.9.0)
cves:
  - id: CVE-2026-7395
    epss: 0.00247
  - id: CVE-2026-11796
    epss: 0.00247
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-03
  - https://www.cve.org/CVERecord?id=CVE-2026-7395
  - https://www.cve.org/CVERecord?id=CVE-2026-11796
rules:
  - title: Detect Unauthorized Access to Asset Suite Administrative Servlets
    description: Detects unauthenticated attempts to access sensitive Asset Suite servlets identified in CVE-2026-7395 and CVE-2026-11796
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict network access to the Asset Suite web interface via firewall
      owner: IT Operations
      due: 24h
      evidence: Advisory recommends minimizing network exposure.
  mitigation_plan:
    - priority: immediate
      action: Disable vulnerable servlets in production
      owner: IT Operations
      addresses: CVE-2026-7395, CVE-2026-11796
      evidence: Vendor mitigation documentation
---

Hitachi Energy has identified multiple vulnerabilities in its Asset Suite product, affecting all versions up to and including 9.9.0. These flaws stem from the lack of authentication mechanisms for critical servlets, which can be reached by unauthenticated network-adjacent attackers. CVE-2026-7395 allows an attacker to interact with the HTTPPublishAdapterTestServlet, facilitating unauthorized configuration file uploads that lead to information disclosure and integrity compromise. Separately, CVE-2026-11796 exposes several other administrative servlets - including PropertiesReloadServlet, CacheFlushServlet, MetadataCacheFlushServlet, and ResourceBundleReloadServlet - allowing attackers to trigger denial-of-service conditions by disrupting application availability. These vulnerabilities affect critical energy infrastructure deployments worldwide.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible web services within the target organization's industrial control network.
2. Attacker confirms the presence of an exposed Hitachi Energy Asset Suite web interface.
3. Attacker identifies the target endpoint for the HTTPPublishAdapterTestServlet (CVE-2026-7395) or management servlets such as CacheFlushServlet (CVE-2026-11796).
4. Attacker sends unauthenticated HTTP GET or POST requests directly to the identified servlets.
5. For CVE-2026-7395, the attacker submits a malicious configuration file to the test servlet, resulting in unauthorized file storage or disclosure.
6. For CVE-2026-11796, the attacker triggers one of the reload or flush servlets, causing the application to enter a denial-of-service state.

## Impact

Successful exploitation of these vulnerabilities can lead to the loss of confidentiality and integrity of system configurations or a disruption of application availability. Given the product's use in the energy sector, such outages may impact the operational integrity of critical infrastructure.

## Recommendation

- Upgrade all instances of Hitachi Energy Asset Suite to version 9.9.1 or later immediately upon availability.
- Disable the vulnerable servlets (HTTPPublishAdapterTestServlet, PropertiesReloadServlet, CacheFlushServlet, MetadataCacheFlushServlet, and ResourceBundleReloadServlet) if they are not required for production operations.
- Restrict network access to the Asset Suite web interface, ensuring it is isolated from the internet and placed behind firewalls with strictly controlled access policies.
- Implement defense-in-depth strategies for all industrial control systems as outlined in the Hitachi Energy Industrial Control Systems Cybersecurity Best Practices notification.
