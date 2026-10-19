---
title: Stored Cross-Site Scripting in IBM Cloud Pak System
slug: 2026-10-ibm-cloud-pak-xss
description: IBM Cloud Pak System versions 2.3.6.0 and 2.3.6.1 contain a stored cross-site scripting (XSS) vulnerability allowing authenticated attackers to inject and execute malicious JavaScript.
date: "2026-10-19T20:12:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:cloud_pak_system:2.3.6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:cloud_pak_system:2.3.6.1:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - cloud
vendors:
  - IBM
products:
  - Cloud Pak System (2.3.6.0, 2.3.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: An authenticated attacker could exploit this vulnerability by entering specially crafted payloads containing malicious JavaScript which are saved within the app.
    confidence_band: high
cves:
  - id: CVE-2026-3295
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3295
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all instances of IBM Cloud Pak System 2.3.6.0 and 2.3.6.1 in the environment.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects specific versions 2.3.6.0 and 2.3.6.1.
  mitigation_plan:
    - priority: immediate
      action: Monitor for software updates from IBM and apply patches for CVE-2026-3295 upon availability.
      owner: IT Operations
      addresses: CVE-2026-3295
      evidence: NVD disclosure indicates the presence of a security vulnerability.
---

IBM Cloud Pak System versions 2.3.6.0 and 2.3.6.1 are affected by a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-3295. This flaw stems from the application failing to properly sanitize or HTML-encode user-supplied input before it is stored in the system and subsequently rendered in the web interface. An authenticated attacker can exploit this by injecting crafted payloads containing malicious JavaScript into the application. Once stored, this script executes automatically within the browser session of any user - including administrators - who views the affected pages. This behavior poses a significant risk to the integrity and confidentiality of user sessions within the management interface of the Cloud Pak System environment.

## Impact

Successful exploitation allows an authenticated attacker to perform unauthorized actions on behalf of other users, potentially leading to session hijacking, unauthorized data access, or the modification of application settings. This vulnerability affects the management web interface of IBM Cloud Pak System 2.3.6.0 and 2.3.6.1, which are typically deployed in enterprise infrastructure management environments.

## Recommendation

Prioritize the identification of IBM Cloud Pak System instances running version 2.3.6.0 or 2.3.6.1 within the environment. Monitor web server logs for suspicious HTTP POST requests containing common XSS vectors (e.g., &lt;script>, onerror, onload, or javascript:) targeted at application entry fields. Ensure that all users are aware of the risks associated with suspicious content in the management interface until an official patch is applied by IBM.
