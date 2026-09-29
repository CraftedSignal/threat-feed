---
title: OS Command Injection in Netcore NAP930 via Network Tools CGI
slug: 2026-09-netcore-cve
description: An unauthenticated remote OS command injection vulnerability in the Netcore NAP930 router allows attackers to execute arbitrary system commands via the sid argument in the network_tools CGI component.
date: "2026-09-29T02:23:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:netcore:nap930:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-device
vendors:
  - Netcore
products:
  - NAP930 (0.1.241010.141410)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument sid results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-102240
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102240
rules:
  - title: Detect CVE-2026-102240 Exploitation - OS Command Injection in Netcore NAP930
    description: Detects exploitation attempts against the Netcore NAP930 network_tools CGI endpoint via shell metacharacters in the sid argument
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
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
    - action: Deploy the provided Sigma rule to web application firewalls or WAF/SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Rule targets the identified vulnerable endpoint and parameter
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the management web interface of affected routers
      owner: IT Operations
      addresses: CVE-2026-102240
      evidence: Source notes vulnerability is remotely exploitable
---

A critical OS command injection vulnerability, identified as CVE-2026-102240, affects the Netcore NAP930 router version 0.1.241010.141410. The vulnerability resides within the Network Tools CGI component, specifically in the /www/cgi-bin/network_tools script. The eval function within this script fails to sanitize the sid argument before processing, allowing unauthenticated remote attackers to inject and execute arbitrary operating system commands. This flaw is particularly dangerous as it grants the attacker execution capabilities with high system privileges. The exploit code is publicly available, increasing the risk of exploitation by opportunistic actors. Despite attempts to contact the vendor, no response or patch has been issued, leaving devices vulnerable. Defenders should monitor for unexpected HTTP requests directed at the network_tools CGI endpoint, particularly those containing shell metacharacters in the query string parameters.

## Impact

Successful exploitation of this vulnerability allows for complete system compromise of the affected Netcore NAP930 router. An attacker can gain persistent unauthorized access, exfiltrate data, or utilize the device as a node in botnet infrastructure. Given the critical CVSS score of 10.0 and public availability of exploit material, there is a high likelihood of automated exploitation attempts across internet-facing devices.

## Recommendation

* Block all inbound access to the web management interface of Netcore NAP930 routers from untrusted or public networks.
* Implement strict access control lists (ACLs) to restrict access to the /www/cgi-bin/network_tools endpoint to known management IP addresses.
* Monitor web server logs for incoming requests to /www/cgi-bin/network_tools that include characters such as semicolon, pipe, or backticks in the 'sid' parameter.
