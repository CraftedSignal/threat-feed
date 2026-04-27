---
title: Cisco Integrated Management Controller (IMC) Multiple XSS Vulnerabilities
slug: 2026-04-cisco-imc-xss
description: Multiple cross-site scripting (XSS) vulnerabilities in the web-based management interface of Cisco Integrated Management Controller (IMC) could allow a remote attacker to conduct an XSS attack against a user of the interface.
date: "2026-04-23T12:00:00Z"
severities:
  - medium
tags:
  - xss
  - cisco
  - cimc
  - vulnerability
vendors:
  - Cisco
products:
  - Integrated Management Controller
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-20085
    cvss: 6.1
    epss: 0.00022
  - id: CVE-2026-20087
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20088
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20089
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20090
    cvss: 4.8
    epss: 0.00036
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-A2tkgVAB
rules:
  - title: Detect Suspicious URI Access to Cisco IMC
    description: Detects suspicious URI access patterns to Cisco IMC web interface which might be related to exploitation of XSS vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Request Containing Script Tags
    description: Detects HTTP requests containing script tags which might indicate XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple cross-site scripting (XSS) vulnerabilities have been identified in the web-based management interface of the Cisco Integrated Management Controller (IMC). Successful exploitation of these vulnerabilities could allow a remote attacker to inject malicious scripts into the web browser of a user accessing the IMC interface. This could lead to session hijacking, sensitive information disclosure, or other malicious activities performed in the context of the user's session. The…
