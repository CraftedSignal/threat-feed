---
title: Multiple Vulnerabilities in Gitea
slug: 2026-04-gitea-vulns
description: Multiple vulnerabilities in Gitea could allow an attacker to disclose information, bypass security measures, and perform cross-site scripting attacks.
date: "2026-04-20T10:29:08Z"
severities:
  - medium
tags:
  - gitea
  - vulnerability
  - xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1172
rules:
  - title: Detect Suspicious Gitea HTTP Requests
    description: Detects suspicious HTTP requests to Gitea instances that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

Multiple vulnerabilities have been identified in Gitea, a self-hosted Git service. These vulnerabilities could be exploited by an attacker to achieve information disclosure, bypass security precautions implemented within the application, and execute cross-site scripting (XSS) attacks. Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive information stored within Gitea repositories, modification of code, or the execution of malicious scripts in the…
