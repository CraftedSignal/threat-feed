---
title: Jupyter Server Authentication Token Leak in Error Logs
slug: 2026-09-jupyter-server-log-leak
description: Jupyter Server versions prior to 2.21.0 inadvertently expose authentication tokens in plain-text 500 error logs due to improper logging of the Referer header.
date: "2026-09-18T01:12:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jupyter:jupyter_server:*:*:*:*:*:*:*:*
tags:
  - credential-exposure
  - logging
  - vulnerability
vendors:
  - Jupyter
products:
  - jupyter_server (< 2.21.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The Referer header was copied into it as-is, so a token in the Referer URL ended up in the logs in plain text.
    confidence_band: high
cves:
  - id: CVE-2026-86049
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-c3mw-737p-c7g2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86049
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade jupyter_server to version 2.21.0 or higher.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 2.21.0 by 5251352.
  mitigation_plan:
    - priority: immediate
      action: Restrict read access on server logs to minimize credential exposure.
      owner: IT Operations
      addresses: CVE-2026-86049
      evidence: Limit who can read the server logs.
---

Jupyter Server versions prior to 2.21.0 contain a security vulnerability (CVE-2026-86049) where sensitive authentication tokens are leaked within server error logs. When a request to the server results in a 500 Internal Server Error, the application logs a JSON block containing the request headers. Specifically, the 'Referer' header is captured and logged without sanitization. Because Jupyter often includes authentication tokens in the URL parameters during standard login and resource launch flows, these tokens are recorded in the logs in plain text. Any individual or service with read access to the server log files can extract these tokens, potentially enabling unauthorized access to the Jupyter environment. This issue highlights the risk of sensitive data exposure through diagnostic logging and emphasizes the need for input sanitization in logging frameworks.

## Impact

Successful exploitation allows local or remote users with log access to harvest valid authentication tokens, potentially leading to account takeover or unauthorized access to Jupyter notebook environments. This vulnerability affects all deployments of Jupyter Server below version 2.21.0. Given the widespread use of Jupyter in data science and research environments, this exposure poses a significant risk to the confidentiality of stored data and compute resources.

## Recommendation

* Upgrade Jupyter Server to version 2.21.0 or later to ensure that header values are scrubbed before being logged.
* Restrict file system permissions on server logs to ensure that only authorized administrative accounts have read access.
* If possible, modify client workflows to avoid passing authentication tokens as URL parameters, opting for headers or cookies where supported.
* Audit existing server logs for patterns matching token structures to identify potentially compromised credentials.
