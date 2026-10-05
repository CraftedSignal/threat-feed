---
title: SSRF Vulnerability in ChatGPTNextWeb NextChat
slug: 2026-10-nextchat-ssrf
description: A server-side request forgery vulnerability in ChatGPTNextWeb NextChat up to version 2.16.1 allows remote attackers to manipulate the x-base-url header to perform unauthorized requests from the application server.
date: "2026-10-05T07:38:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chatgptnextweb:nextchat:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
vendors:
  - ChatGPTNextWeb
products:
  - NextChat (<= 2.16.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This manipulation of the argument x-base-url causes server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-105238
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105238
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict egress traffic from the application server to non-essential internal and external destinations
      owner: IT Operations
      due: 24h
      evidence: Mitigation of SSRF risk
  hunt_leads:
    - lead: Analyze web server logs for HTTP requests containing x-base-url headers with internal IP addresses
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves manipulation of x-base-url argument
  mitigation_plan:
    - priority: immediate
      action: Upgrade NextChat to the patched version once released
      owner: IT Operations
      addresses: CVE-2026-105238
      evidence: Official vendor update pending
---

ChatGPTNextWeb NextChat versions up to and including 2.16.1 contain a server-side request forgery (SSRF) vulnerability. The flaw exists within the proxyHandler function located in app/api/proxy.ts, specifically within the component responsible for proxy fallback handling. By manipulating the 'x-base-url' HTTP header, an unauthenticated remote attacker can force the application server to make arbitrary requests to internal or external resources. This can potentially expose sensitive internal services, metadata endpoints, or infrastructure otherwise protected by network boundaries. While a fix has been proposed via pull request, it remains pending acceptance at the time of reporting. Organizations utilizing NextChat should monitor for suspicious outbound traffic patterns originating from the server hosting the application until an official patch is verified and deployed.

## Impact

Successful exploitation of this SSRF vulnerability permits unauthorized interaction with resources reachable by the application server. This could lead to information disclosure, unauthorized access to internal management interfaces, or service disruption. As the vulnerability is remotely exploitable without authentication, it poses a significant risk to the integrity of internal network segments hosting the application.

## Recommendation

* Monitor HTTP traffic for unexpected requests originating from the NextChat application server to sensitive internal IP ranges or cloud metadata services (e.g., 169.254.169.254).
* Restrict the application server's outbound network access to only necessary external endpoints via egress firewall rules.
* Review the pending security patches provided by the project maintainers and update to a remediated version once finalized and released.
