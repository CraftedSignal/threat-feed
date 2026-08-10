---
title: Remote Command Injection in EFM ipTIME AX8004M
slug: 2026-08-iptime-rce
description: The EFM ipTIME AX8004M router version 15.09.0 is vulnerable to remote command injection via the /cgi/d.cgi CGI endpoint, allowing unauthenticated attackers to execute arbitrary system commands.
date: "2026-08-10T01:50:07Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - EFM
products:
  - ipTIME AX8004M (15.09.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: This manipulation of the argument fname causes os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19379
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19379
rules:
  - title: Detects CVE-2026-19379 Exploitation - Command Injection via cgi/d.cgi
    description: Detects potential command injection attempts targeting the vulnerable ipTIME AX8004M CGI endpoint by monitoring for shell metacharacters in the fname parameter.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to the /cgi/d.cgi endpoint on ipTIME AX8004M devices via perimeter firewall.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19379 vulnerability disclosure
  hunt_leads:
    - lead: Search logs for HTTP GET/POST requests containing shell metacharacters targeting the /cgi/d.cgi endpoint.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies the vulnerability vector as the fname argument in /cgi/d.cgi.
  mitigation_plan:
    - priority: immediate
      action: Isolate affected ipTIME routers from the public internet until a vendor patch is released.
      owner: IT Operations
      addresses: CVE-2026-19379
      evidence: No vendor response noted in source material.
---

The EFM ipTIME AX8004M router (firmware version 15.09.0) contains a critical remote command injection vulnerability, tracked as CVE-2026-19379. The flaw originates in the handling of the 'fname' argument within the 'popen' function of the '/cgi/d.cgi' component. Because this endpoint fails to properly sanitize user-supplied input before passing it to the underlying system shell, an unauthenticated remote attacker can inject and execute arbitrary commands with the privileges of the web server process. This vulnerability is significant due to the device's role as a network gateway, potentially providing attackers with a foothold to intercept traffic, perform lateral movement, or conduct further exploitation within the internal network. Disclosure of this vulnerability has occurred publicly without a corresponding vendor patch, leaving deployed devices exposed to potential exploitation attempts.

## Attack Chain

1. Attacker performs reconnaissance to identify ipTIME AX8004M devices reachable via the internet.
2. Attacker probes the target for the presence of the vulnerable '/cgi/d.cgi' endpoint.
3. Attacker constructs an HTTP GET or POST request targeting the 'fname' parameter.
4. Attacker inserts shell metacharacters (e.g., semicolon, pipe, backticks) into the 'fname' argument string.
5. The web server process passes the unsanitized 'fname' string to the 'popen' function.
6. The underlying system shell interprets the injected metacharacters and executes the attacker's payload.
7. Attacker gains remote command execution on the router, establishing persistence or exfiltrating data.

## Impact

Successful exploitation allows for full remote compromise of the ipTIME AX8004M router. Impacted organizations and residential users face the risk of total device takeover, which can facilitate man-in-the-middle attacks, credential theft, or the use of the router as a node in a botnet. As of the current disclosure, no vendor-provided patch exists, making immediate network-level isolation or firewalling of management interfaces the only viable mitigation.

## Recommendation

* Monitor ingress traffic to internal networks for HTTP requests directed toward the '/cgi/d.cgi' URI stem.
* Implement strict firewall rules to prevent remote access to router management interfaces from untrusted or public IP addresses.
* Audit logs for suspicious command execution patterns originating from web service processes on network appliances.
