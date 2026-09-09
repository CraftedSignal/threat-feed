---
title: Fortinet FortiSIEM Open Redirect Vulnerability
slug: 2026-09-fortinet-fortisiem-open-redirect
description: A vulnerability in Fortinet FortiSIEM allows a remote, unauthenticated attacker to perform an open redirect, enabling the redirection of users to malicious or untrusted websites.
date: "2026-09-09T12:50:09Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - webserver
  - informational
vendors:
  - Fortinet
products:
  - FortiSIEM (< 4.7.1)
cves:
  - id: CVE-2024-47576
    cvss: 3.3
    epss: 0.00184
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3261
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47576
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: short_term
      action: Patch FortiSIEM to 4.7.1 or later
      owner: IT Operations
      addresses: CVE-2024-47576
      evidence: Official security advisory for CVE-2024-47576.
---

Fortinet has identified a vulnerability in FortiSIEM that exposes users to an open redirect attack. A remote, unauthenticated attacker can exploit this flaw to manipulate URL parameters, causing the application to redirect authenticated or unauthenticated users to a site of the attacker's choosing. This type of vulnerability is frequently leveraged in phishing campaigns, where attackers use trusted domain names to lend credibility to malicious links, increasing the likelihood that users will navigate to credential harvesting or malware delivery sites. Defenders should prioritize auditing web traffic logs for suspicious redirect patterns originating from their FortiSIEM infrastructure.

## Impact

Successful exploitation allows attackers to conduct more convincing social engineering and phishing attacks by leveraging the reputation of a legitimate organization's infrastructure. While this vulnerability does not provide direct access to the underlying server, it facilitates the compromise of end-user credentials and increases the success rate of subsequent endpoint exploitation attempts.

## Recommendation

Prioritize applying the vendor-supplied security patch to the affected FortiSIEM installation as specified in the official Fortinet security advisory. Monitor web access logs for anomalous redirect targets, specifically identifying URLs that navigate outside of the organization's sanctioned domain space.
