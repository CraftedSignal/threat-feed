---
title: Remote Code Execution in Halo via Plugin and Migration Vulnerabilities
slug: 2026-08-halo-rce-chain
description: Halo versions up to 2.25.4 are vulnerable to RCE through insecure plugin installation and migration restoration processes, which can be chained with CSRF to allow unauthenticated attackers to compromise an instance if an administrator visits a malicious page.
date: "2026-08-19T16:41:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Halohub
products:
  - Halo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: halo's console lets admins install and upgrade plugins by pasting a url. it fetches whatever url, installs the jar, and the jar's code runs on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: a page the admin visits can do it all with fetch(). see exploit/csrf.html.
    confidence_band: high
cves:
  - id: CVE-2026-67919
    cvss: 9.8
    epss: 0.00293
  - id: CVE-2026-67920
  - id: CVE-2026-67921
references:
  - https://sploitus.com/exploit?id=2DCD3BB6-8EED-5D26-AE57-60BB3EC94C6A
rules:
  - title: Detect Exploitation of Halo Plugin RCE
    description: Detects potential exploitation of CVE-2026-67919 by identifying suspicious POST requests to the plugin installation API endpoints with external URL parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy web server rule to monitor or block POST requests to Halo plugin API endpoints.
      owner: Detection Engineering
      due: 24h
      evidence: Source document confirms the plugin install mechanism is the RCE vector.
---

Researchers have disclosed a chain of vulnerabilities in the Halo CMS (up to version 2.25.4) that facilitates remote code execution (RCE). The primary vulnerability, CVE-2026-67919, stems from the plugin installation and upgrade feature, which fetches and executes arbitrary JAR files from a user-supplied URL without verifying the source or destination. This is compounded by CVE-2026-67920, an insecure migration restore function that allows attackers to overwrite system extension directories, and CVE-2026-67921, a CSRF/CORS vulnerability that allows an attacker to bypass authentication requirements. By tricking an authenticated administrator into visiting a malicious webpage, an attacker can trigger the plugin or migration primitives, leading to full server-side code execution. Given the availability of public proof-of-concept (PoC) code and the high CVSS score (9.8), organizations running Halo should prioritize patching or restricting access to the console until a fix is deployed.

## Attack Chain

1. Attacker constructs a malicious plugin JAR file containing arbitrary Java code and hosts it on an externally accessible web server.
2. Attacker hosts a malicious webpage (CSRF/CORS trigger) that, when visited by an administrator, performs cross-origin fetch requests to the Halo instance console.
3. The victim administrator, who is already authenticated to the Halo console, visits the attacker-controlled webpage.
4. The browser automatically includes the victim's session cookies with the request to the Halo API due to permissive CORS settings and 'SameSite=None' cookies.
5. The attacker-controlled JavaScript executes an 'install-from-uri' or 'upgrade-from-uri' call to the Halo Plugin Manager API, pointing to the malicious JAR hosted in step 1.
6. The Halo server fetches the malicious JAR from the attacker's server and proceeds to load and execute the contained Java classes within the application runtime.
7. The attacker's code runs with the privileges of the Halo application service, allowing for persistent backdoor installation or full system compromise.

## Impact

Successful exploitation allows unauthenticated remote attackers to achieve full code execution on the server hosting the Halo instance. This leads to complete system compromise, including the potential for data exfiltration, system destruction via the migration restore mechanism (which wipes existing configurations), and lateral movement within the target environment.

## Recommendation

* Immediately restrict network access to the Halo administration console to trusted internal IP addresses only.
* Audit all currently installed plugins in the Halo instance to ensure they match known, legitimate sources.
* Monitor web server logs for suspicious POST requests to the `/api/plugins/install-from-uri` or `/api/plugins/upgrade-from-uri` endpoints, specifically those originating from external, unexpected hosts.
* If a fix is not immediately available, use firewall or WAF rules to block access to the `/api/plugins/` and `/api/migration/` endpoints from external sources.
