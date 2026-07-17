---
title: Vulnerability in poco-ai poco-claw Leads to Server-Side Request Forgery (CVE-2026-16016)
slug: 2026-07-poco-claw-ssrf
description: A high-severity server-side request forgery (SSRF) vulnerability, identified as CVE-2026-16016, exists in poco-ai's poco-claw software up to version 0.5.4, allowing remote attackers to manipulate the `callback_url` argument in the `run_task` function to force the server to make arbitrary requests, with a public exploit available posing an immediate risk.
date: "2026-07-17T14:18:18Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - server-side-request-forgery
  - ssrf
  - web-vulnerability
  - python
  - remote-code-execution
  - cve
vendors:
  - poco-ai
products:
  - poco-claw <= 0.5.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was identified in poco-ai poco-claw up to 0.5.4. This issue affects the function run_task of the file executor/app/api/v1/task.py. The manipulation of the argument callback_url leads to server-side request forgery. The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1090
    technique_name: Proxy
    evidence: The manipulation of the argument callback_url leads to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-16016
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16016
rules:
  - title: Detect Potential Server-Side Request Forgery to Private IPs
    description: Detects outbound network connections from a server to private IP address ranges, which can indicate successful exploitation of Server-Side Request Forgery (SSRF) vulnerabilities like CVE-2026-16016.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - impact
    techniques:
      - T1565
      - T1592.001
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A high-severity server-side request forgery (SSRF) vulnerability, tracked as CVE-2026-16016, has been identified in `poco-ai poco-claw` versions up to and including 0.5.4. This flaw specifically affects the `run_task` function located within the `executor/app/api/v1/task.py` file. Attackers can exploit this vulnerability by manipulating the `callback_url` argument, compelling the affected `poco-claw` instance to initiate arbitrary requests to internal or external systems. The vulnerability can be exploited remotely, and a public exploit is known to be available, indicating an increased risk of active exploitation. Defenders should prioritize patching and monitoring for unusual outbound connections from affected systems to mitigate potential information disclosure or internal network access.

## Attack Chain

1. An attacker discovers an internet-facing instance of `poco-ai poco-claw` version 0.5.4 or earlier.
2. The attacker crafts an HTTP POST request targeting the `run_task` function exposed via the `/api/v1/task.py` endpoint on the vulnerable server.
3. Within the request, the attacker provides a maliciously constructed internal or external URL as the value for the `callback_url` argument.
4. The vulnerable `poco-claw` application, lacking proper input validation for the `callback_url` parameter, processes the `run_task` request.
5. The `run_task` function initiates an outbound HTTP request from the `poco-claw` host to the URL specified by the attacker in `callback_url`.
6. This server-side request is performed by the `poco-claw` instance, allowing the attacker to interact with internal network resources, bypass firewall restrictions, or perform network scans from the server's context.
7. The attacker receives or infers the response to the SSRF-induced request, gathering information about internal services or performing actions on behalf of the `poco-claw` server.
8. This gained access or information can then be leveraged for further reconnaissance, lateral movement within the network, or data exfiltration.

## Impact

Successful exploitation of CVE-2026-16016 leads to server-side request forgery, which can have significant consequences. Attackers can leverage this to bypass network access controls, scan internal networks, access sensitive internal services, or exfiltrate data from systems that are otherwise unreachable from the internet. The remote exploitability and public availability of exploit code increase the likelihood of widespread attacks, potentially leading to unauthorized access to critical internal infrastructure and sensitive information.

## Recommendation

* Patch all `poco-ai poco-claw` instances to a version greater than 0.5.4 immediately to remediate CVE-2026-16016.
* Deploy the Sigma rule "Detect Potential Server-Side Request Forgery to Private IPs" to your SIEM and tune it for your environment.
* Enable comprehensive network connection logging for servers running `poco-claw` applications to monitor for unusual outbound requests.
* Implement outbound firewall rules to restrict network connections initiated by the `poco-claw` application only to necessary and approved destinations.
