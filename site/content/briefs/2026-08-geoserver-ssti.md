---
title: GeoServer Server-Side Template Injection Vulnerability
slug: 2026-08-geoserver-ssti
description: An authenticated administrator can exploit a server-side template injection (SSTI) vulnerability in GeoServer's FreeMarker engine to execute arbitrary OS commands and perform unauthorized file operations.
date: "2026-08-19T22:33:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - geoserver
vendors:
  - GeoServer
products:
  - gs-main
  - gs-wms
  - gs-web-app
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated administrator can upload FreeMarker templates containing malicious content that can execute OS commands.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wf6j-gr27-g7ch
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade GeoServer to version 2.27.0 or higher
      owner: IT Operations
      due: 48h
      evidence: GeoServer 2.27.0 addresses this vulnerability
  mitigation_plan:
    - priority: immediate
      action: Enable and configure GEOSERVER_FREEMARKER_BLOCK_LIST and GEOSERVER_FREEMARKER_ALLOW_LIST
      owner: IT Operations
      addresses: CVE-2024-45747
      evidence: New application properties default to restricting the objects template authors can access
---

GeoServer contains a server-side template injection (SSTI) vulnerability, tracked as CVE-2024-45747, affecting versions prior to 2.27.0. The vulnerability resides in the processing engine for FreeMarker templates used in WMS output formats, specifically GetFeatureInfo (HTML and JSON) and GetMap (KML and GeoRSS). While the internal method org.geoserver.template.TemplateUtils.getSafeConfiguration() is designed to restrict access to the freemarker.template.utility.Execute class, attackers can bypass these protections by chaining specific method calls. This flaw allows an authenticated administrator to upload malicious templates, ultimately resulting in remote code execution (RCE) and arbitrary file read/write operations on the hosting server. Defenders should note that this vulnerability requires administrative authentication, making the protection of administrative credentials and session management critical for risk mitigation.

## Attack Chain

1. Attacker obtains or creates an authenticated administrative session to the target GeoServer instance.
2. Attacker navigates to the WMS output settings or administrative template management interface.
3. Attacker crafts a malicious FreeMarker template designed to chain method calls that bypass the TemplateUtils restriction.
4. Attacker uploads the crafted template through the administrative web interface.
5. Attacker triggers the WMS GetFeatureInfo or GetMap functionality to invoke the injected template processing.
6. The server-side FreeMarker engine processes the template, failing to restrict access to sensitive utility classes.
7. Malicious code executes with the privileges of the GeoServer application process.
8. Attacker achieves remote code execution or unauthorized access to the filesystem.

## Impact

Successful exploitation allows an authenticated attacker to gain full control over the GeoServer instance through remote code execution. Furthermore, the ability to read and write arbitrary files on the server enables the extraction of sensitive configuration data, credentials, or the modification of application logic to establish persistence. This vulnerability affects multiple core components of the GeoServer ecosystem, including gs-main, gs-wms, and gs-web-app.

## Recommendation

1. Upgrade all GeoServer deployments to version 2.27.0 or later to patch CVE-2024-45747.
2. Configure the new application properties GEOSERVER_FREEMARKER_BLOCK_LIST and GEOSERVER_FREEMARKER_ALLOW_LIST to enforce strict access controls on FreeMarker template object access.
3. Monitor administrative logs for unauthorized or unexpected template uploads and modifications.
4. Restrict access to administrative interfaces to trusted management subnets to mitigate the prerequisite authentication requirement.
