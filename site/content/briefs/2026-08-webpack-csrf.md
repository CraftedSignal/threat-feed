---
title: CSRF Vulnerability in webpack-dev-server
slug: 2026-08-webpack-csrf
description: A CSRF vulnerability (CVE-2026-14620) in webpack-dev-server 5.2.5 allows unauthenticated cross-origin requests to trigger the launchEditor() function, potentially enabling remote command execution via arbitrary local file paths.
date: "2026-08-17T14:53:49Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:webpack.js:webpack-dev-server:*:*:*:*:*:*:*:*
tags:
  - webapps
  - csrf
  - cve-2026-14620
products:
  - webpack-dev-server (5.2.5)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can exploit this by crafting a cross-origin request using fetch (with CORS mode) or browser navigation to trigger the launchEditor() function.
    confidence_band: med
cves:
  - id: CVE-2026-14620
    cvss: 4.7
    epss: 0.00149
  - id: CVE-2026-6402
    cvss: 5.3
    epss: 0.00216
references:
  - https://www.exploit-db.com/exploits/52649
  - https://github.com/Pig-Tail/security-research/tree/master/CVE-2026-14620-webpack-dev-server
rules:
  - title: Detect Exploitation of CVE-2026-14620 - CSRF to open-editor
    description: Detects unauthorized cross-origin attempts to access the open-editor endpoint of webpack-dev-server via browser navigation or CORS requests.
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
    - Detection Engineering
  immediate_actions:
    - action: Audit webpack-dev-server instances to identify version 5.2.5 or lower.
      owner: IT Operations
      due: 24h
      evidence: Affected version is <= 5.2.5.
  mitigation_plan:
    - priority: immediate
      action: Upgrade webpack-dev-server to 5.2.6 or higher.
      owner: IT Operations
      addresses: CVE-2026-14620
      evidence: Fixed in 5.2.6.
---

The webpack-dev-server package, a widely used development tool for web applications, contains a CSRF vulnerability in versions 5.2.5 and below. The vulnerability exists within the /webpack-dev-server/open-editor endpoint, which is designed to open project files in a local editor. Research demonstrates that the security guard intended to prevent cross-origin access (implemented for CVE-2026-6402) is insufficient because it only restricts requests with specific headers (sec-fetch-mode: no-cors). 

An attacker can bypass this restriction using cross-site navigations (e.g., iframes, window.open) or fetch requests configured with mode: 'cors'. By invoking this endpoint from a malicious web page, an attacker can trigger the launchEditor() function on a developer's machine. This allows the attacker to force the execution of arbitrary existing files on the host filesystem, potentially leading to command execution depending on the configured editor environment. This issue was identified as CVE-2026-14620 and is tracked under GHSA-f5vj-f2hx-8m93.

## Attack Chain

1. Attacker hosts a malicious website designed to execute cross-origin requests toward a victim's local developer environment.
2. The victim, who is currently running a local instance of webpack-dev-server 5.2.5, navigates to the attacker-controlled website.
3. The malicious website triggers an iframe or a fetch request with mode: 'cors' directed at the local development server on port 8080 (or the configured port).
4. The request reaches the /webpack-dev-server/open-editor?fileName= endpoint on the local webpack-dev-server.
5. The server fails to validate the origin of the 'navigate' or 'cors' request and passes the fileName parameter to the launchEditor() function.
6. The launchEditor() function executes the local system's default editor (or the one defined in LAUNCH_EDITOR) using the attacker-supplied file path.
7. The target file is opened in the local editor environment, which may result in arbitrary process execution if the editor is configured to interpret or run the targeted file.

## Impact

Successful exploitation allows an attacker to interact with the filesystem of a developer's workstation by proxying requests through the browser. This can lead to the unintended execution of local files or the exposure of sensitive source code and environment configuration, impacting the integrity of the development environment.

## Recommendation

* Upgrade webpack-dev-server to version 5.2.6 or later to apply the fix for CVE-2026-14620.
* In the absence of an immediate upgrade, restrict access to the development server by binding it to localhost and utilizing firewall rules to prevent inbound traffic from untrusted networks.
* Review all custom editor launch configurations, as these environment variables may influence the severity of the code execution outcome.
