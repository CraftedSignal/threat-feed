---
title: Remote Command Injection in TOTOLINK X5000R
slug: 2026-09-totolink-rce
description: A remote OS command injection vulnerability in the TOTOLINK X5000R router allows unauthenticated attackers to execute arbitrary commands via the exportOvpn function.
date: "2026-09-15T17:46:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:totolink:x5000r:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve-2026-91853
  - network-security
vendors:
  - TOTOLINK
products:
  - X5000R (9.1.0cu.2089_B20211224)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument filetype leads to os command injection. The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-91853
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91853
rules:
  - title: Detects CVE-2026-91853 Exploitation - Command Injection in TOTOLINK ExportOvpn
    description: Detects attempts to exploit CVE-2026-91853 by identifying suspicious manipulation of the filetype parameter in the exportOvpn cgi script.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule for web server logs
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search logs for requests to /cgi-bin/cstecgi.cgi containing shell metacharacters
      technique_id: T1203
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of command injection vulnerability in cstecgi.cgi
---

The TOTOLINK X5000R router, specifically version 9.1.0cu.2089_B20211224, is susceptible to an OS command injection vulnerability (CVE-2026-91853). The vulnerability resides within the exportOvpn handler, which is invoked via the /cgi-bin/cstecgi.cgi script. An attacker can trigger this flaw by manipulating the filetype argument during an export request. Because the application fails to properly sanitize user-supplied input before passing it to the underlying system shell, an unauthenticated remote attacker can achieve arbitrary code execution. This vulnerability is publicly disclosed, increasing the risk of exploitation by opportunistic actors targeting edge network infrastructure. Defenders should monitor web server logs for suspicious requests directed at the exportOvpn handler.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary operating system commands on the affected router. This could result in full device compromise, unauthorized access to internal network traffic, and the use of the router as a pivot point for further lateral movement within the environment.

## Recommendation

- Monitor web server traffic for HTTP requests targeting /cgi-bin/cstecgi.cgi with suspicious parameters in the filetype argument.
- Implement access control lists on edge firewalls to restrict access to the web management interface of affected TOTOLINK routers to trusted IP ranges only.
- Audit network logs for anomalous outbound connections originating from router infrastructure.
