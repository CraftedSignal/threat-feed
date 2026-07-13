---
title: Spring Boot Admin Server SSRF Vulnerability (CVE-2026-62242)
slug: 2026-07-spring-boot-admin-ssrf
description: An unauthenticated attacker can exploit CVE-2026-62242, a server-side request forgery vulnerability in Spring Boot Admin Server before 4.1.2, to force the server to make requests to arbitrary internal addresses and exfiltrate sensitive data, including cloud credentials.
date: "2026-07-13T22:32:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - server-side-request-forgery
  - spring-boot-admin
  - vulnerability
  - cloud-security
vendors:
  - codecentric
products:
  - Spring Boot Admin Server (before 4.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: allows unauthenticated attackers to register instances with attacker-controlled healthUrl and managementUrl parameters
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Attackers can force the server to make HTTP requests to arbitrary internal addresses
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: force the server to make HTTP requests to ... metadata endpoints.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: retrieve response bodies via the actuator proxy to exfiltrate cloud credentials.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
    evidence: exfiltrate cloud credentials
    confidence_band: high
cves:
  - id: CVE-2026-62242
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62242
  - https://github.com/codecentric/spring-boot-admin/commit/1f991ea013e46360b8f8fb63fe4ad20a9bf0d551
  - https://github.com/codecentric/spring-boot-admin/issues/5452
  - https://github.com/codecentric/spring-boot-admin/pull/5464
  - https://github.com/codecentric/spring-boot-admin/releases/tag/4.1.2
  - https://www.vulncheck.com/advisories/spring-boot-admin-server-ssrf-via-unauthenticated-instance-registration
---

Spring Boot Admin Server versions prior to 4.1.2 are affected by CVE-2026-62242, a critical server-side request forgery (SSRF) vulnerability. This flaw allows an unauthenticated attacker to register new instances on the server by providing attacker-controlled `healthUrl` and `managementUrl` parameters. Crucially, the server fails to validate these URLs against private IP ranges or cloud metadata endpoints. This lack of validation enables the attacker to coerce the Spring Boot Admin Server into initiating HTTP requests to arbitrary internal network addresses or sensitive cloud metadata services. Subsequently, the attacker can leverage the server's actuator proxy functionality to retrieve the response bodies from these internal requests, leading to the potential exfiltration of sensitive information, such as cloud credentials.

## Attack Chain

1. An unauthenticated attacker sends a crafted registration request to the vulnerable Spring Boot Admin Server.
2. The registration request includes malicious `healthUrl` and `managementUrl` parameters, pointing to internal network IP addresses or cloud metadata endpoints (e.g., `169.254.169.254`).
3. The Spring Boot Admin Server, due to the SSRF vulnerability (CVE-2026-62242), processes these unvalidated URLs without restricting access to private resources.
4. The server then initiates HTTP GET requests to the internal arbitrary addresses or cloud metadata endpoints specified by the attacker.
5. The server's actuator proxy component retrieves the response bodies from these internal requests, which may contain sensitive data.
6. The attacker then accesses the Spring Boot Admin Server's functionality to retrieve the proxied response bodies, effectively exfiltrating the internal data, such as cloud credentials.

## Impact

Successful exploitation of CVE-2026-62242 grants unauthenticated attackers the ability to perform server-side request forgery, bypassing network segmentation and accessing internal resources. This can lead to sensitive information disclosure, particularly the exfiltration of cloud credentials from metadata endpoints. Compromised cloud credentials can enable further lateral movement within cloud environments, leading to unauthorized access to cloud resources, data manipulation, or complete compromise of cloud accounts, posing a significant risk to the integrity and confidentiality of an organization's cloud infrastructure.

## Recommendation

* Patch Spring Boot Admin Server instances immediately to version 4.1.2 or later to mitigate CVE-2026-62242.
* Monitor web server logs for unauthenticated registration attempts that include `healthUrl` or `managementUrl` parameters pointing to internal IP addresses or cloud metadata endpoints.
* Ensure network segmentation and firewall rules are in place to restrict outbound connections from Spring Boot Admin Server instances to internal networks and sensitive services.
