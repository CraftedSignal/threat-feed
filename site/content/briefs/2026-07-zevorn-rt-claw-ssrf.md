---
title: Server-Side Request Forgery in zevorn rt-claw (CVE-2026-16128)
slug: 2026-07-zevorn-rt-claw-ssrf
description: A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-16128, exists in zevorn rt-claw versions up to and including 0.2.0. The flaw is located within the `receiver_thread` function of the `http_request` component in `claw/services/swarm/swarm.c`. This critical vulnerability allows remote attackers to perform server-side request forgery, and a public exploit is available, increasing the urgency for detection and mitigation efforts.
date: "2026-07-18T17:18:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - webserver
  - remote-code-execution
  - information-disclosure
vendors:
  - zevorn
products:
  - rt-claw 0.1
  - rt-claw 0.2.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: ""
    evidence: Performing a manipulation results in server-side request forgery.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Performing a manipulation results in server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-16128
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16128
  - https://github.com/zevorn/rt-claw/
  - https://github.com/zevorn/rt-claw/issues/140
  - https://vuldb.com/cve/CVE-2026-16128
  - https://vuldb.com/submit/856873
  - https://vuldb.com/vuln/379840
  - https://vuldb.com/vuln/379840/cti
iocs:
  - type: url
    value: https://github.com/zevorn/rt-claw/issues/140
  - type: url
    value: https://vuldb.com/cve/CVE-2026-16128
  - type: url
    value: https://vuldb.com/submit/856873
  - type: url
    value: https://vuldb.com/vuln/379840
  - type: url
    value: https://vuldb.com/vuln/379840/cti
ioc_counts:
  url: 5
---

A severe server-side request forgery (SSRF) vulnerability, tracked as CVE-2026-16128, has been identified in `zevorn rt-claw` software, specifically affecting versions up to and including 0.2.0. The flaw resides within the `receiver_thread` function in the `http_request` component of `claw/services/swarm/swarm.c`. This vulnerability allows a remote unauthenticated attacker to manipulate HTTP requests, compelling the vulnerable `rt-claw` application to make arbitrary requests to internal or external systems from the server's perspective. An exploit for CVE-2026-16128 has been publicly released, increasing the risk of widespread attacks. The project maintainers were notified via an issue report but have not yet responded or released a patch, leaving affected systems exposed to potential data exfiltration, internal network reconnaissance, or further compromise.

## Attack Chain

1. A remote attacker crafts a malicious HTTP request targeting a `zevorn rt-claw` instance running a vulnerable version (up to 0.2.0).
2. The malicious request exploits a flaw in the `receiver_thread` function within the `http_request` component.
3. The `rt-claw` application processes the manipulated request, leading it to initiate an arbitrary HTTP request to a target specified by the attacker.
4. This server-side request forgery (SSRF) allows the attacker to leverage the `rt-claw` server as a proxy to access internal network resources (e.g., administrative interfaces, cloud metadata services, other internal APIs) that are otherwise inaccessible from outside.
5. The `rt-claw` server returns the response from the internal or external target to the attacker, facilitating information disclosure or potential interaction with these services.
6. The attacker can use the gained information or access to pivot further into the internal network, exfiltrate sensitive data, or potentially achieve remote code execution depending on the accessed services.

## Impact

Successful exploitation of CVE-2026-16128 can lead to significant information disclosure and network access within the victim's environment. Attackers can perform internal network reconnaissance, access sensitive internal services, retrieve credentials from cloud metadata services, and potentially interact with internal APIs or databases. Given that a public exploit is available and the vendor has not yet responded with a patch, organizations running `zevorn rt-claw` are at high risk of compromise, which could result in data breaches, further system compromise, and operational disruption.

## Recommendation

* Organizations using `zevorn rt-claw` should immediately assess their deployments for versions up to 0.2.0, as these are affected by CVE-2026-16128.
* Isolate affected systems from critical internal networks to minimize the blast radius of potential SSRF exploitation of CVE-2026-16128.
* Monitor web server logs (category `webserver`) for unusual HTTP requests to `zevorn rt-claw` endpoints, specifically looking for crafted parameters that might indicate SSRF attempts related to CVE-2026-16128.
* Implement egress filtering on network devices to prevent the `zevorn rt-claw` application from making outbound requests to unauthorized internal IP ranges or sensitive external services.
* As the vendor has not yet provided a patch for CVE-2026-16128, consider implementing web application firewall (WAF) rules to detect and block requests attempting to exploit this vulnerability by sanitizing or blocking suspicious URL parameters.
