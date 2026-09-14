---
title: CVE-2026-90937 Configuration Injection in Froxlor
slug: 2026-09-froxlor-config-injection
description: Froxlor versions before 2.2.5 contain a vulnerability allowing authenticated users to inject arbitrary Nginx or Apache configuration directives via unvalidated newline characters in subdomain redirect URLs.
date: "2026-09-14T17:34:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:froxlor:froxlor:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - configuration-injection
  - server-hijacking
vendors:
  - Froxlor
products:
  - froxlor (< 2.2.5)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The vulnerability allows an authenticated customer to inject arbitrary nginx or Apache configuration directives which are written into vhost config files during cron rebuild.
    confidence_band: high
cves:
  - id: CVE-2026-90937
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90937
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Froxlor to version 2.2.5 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90937 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Froxlor 2.2.5
      owner: IT Operations
      addresses: CVE-2026-90937
      evidence: Source vendor advisory.
---

Froxlor versions prior to 2.2.5 fail to perform adequate input validation on subdomain redirect URLs within the administrative interface. An authenticated customer can submit a crafted URL containing literal newline characters (\n or \r\n). When the froxlor cron job triggers a configuration rebuild for the web server, these newline characters are written verbatim into the generated vhost configuration files for Nginx or Apache.

This injection allows an attacker to terminate existing configuration lines and introduce entirely new directives into the web server context. This can lead to the hijacking of HTTP responses across other hosted domains, redirection of traffic to malicious destinations, or denial of service through the injection of syntax errors that prevent web server service restarts. Defenders should prioritize updating to version 2.2.5 or later to enforce proper sanitization of redirect parameters.

## Attack Chain

1. Attacker authenticates to the froxlor customer panel.
2. Attacker navigates to the subdomain management section.
3. Attacker submits a new or existing subdomain redirect URL containing injected newline characters followed by malicious web server directives (e.g., 'https://site.com\nrewrite ^/ /malicious_path').
4. The input is persisted in the backend database without validation.
5. The server-side cron job executes, invoking the configuration generator script.
6. The script retrieves the malicious input and writes it to the active Nginx or Apache vhost configuration file.
7. The system reloads the web server configuration to apply changes.
8. Web server processes the injected directives, leading to hijacking or service disruption.

## Impact

Successful exploitation allows an authenticated user to perform service-wide configuration corruption. This enables attackers to hijack HTTP responses for unrelated domains hosted on the same infrastructure, bypass security controls, or cause a denial of service for the entire web server instance.

## Recommendation

* Upgrade Froxlor to version 2.2.5 or later immediately.
* Review web server configuration files for unexpected directives, particularly those following subdomain definitions.
* Audit logs for customer panel activity specifically looking for URL inputs containing newline characters.
