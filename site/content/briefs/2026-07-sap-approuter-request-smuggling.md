---
title: SAP Approuter HTTP Request Smuggling Vulnerability Allows Confidentiality and Availability Impact (CVE-2026-27690)
slug: 2026-07-sap-approuter-request-smuggling
description: An HTTP Request Smuggling vulnerability (CVE-2026-27690, CWE-444) in SAP Approuter allows an unauthenticated attacker to send a specially crafted HTTP request leading to request-response desynchronization, which can result in the exposure of user responses and cause a denial of service by making the system unavailable.
date: "2026-07-14T01:17:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - http-request-smuggling
  - vulnerability
  - sap
  - web-application
  - denial-of-service
  - data-exposure
vendors:
  - SAP SE
products:
  - SAP Approuter node.js package
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Due to an HTTP Request Smuggling vulnerability in SAP Approuter, an unauthenticated attacker could send a specially crafted HTTP request
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: This could result in the exposure of user responses
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: and cause the system to become unavailable.
    confidence_band: high
cves:
  - id: CVE-2026-27690
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27690
  - https://me.sap.com/notes/3720138
  - https://url.sap/sapsecuritypatchday
---

SAP Approuter, specifically versions older than 20.10.0 of its Node.js package, is affected by a critical HTTP Request Smuggling vulnerability, identified as CVE-2026-27690 (CWE-444). This flaw allows an unauthenticated attacker to manipulate HTTP requests, leading to request-response desynchronization between a frontend proxy/load balancer and the backend Approuter server. By exploiting this desynchronization, an attacker can expose sensitive user responses, compromising confidentiality. Furthermore, the vulnerability can also be leveraged to trigger internal server errors or resource exhaustion, effectively rendering the system unavailable and leading to a denial of service. The vulnerability has a CVSS v3.1 base score of 9.1, indicating a severe risk to affected deployments.

## Attack Chain

1. An unauthenticated attacker identifies an internet-facing SAP Approuter instance vulnerable to HTTP Request Smuggling.
2. The attacker crafts a malicious HTTP request that uses conflicting methods for determining message length (e.g., `Content-Length` and `Transfer-Encoding: chunked`) to exploit differences in how a frontend proxy/load balancer and the backend Approuter server process the request.
3. The frontend proxy/load balancer processes the request according to one method, while the backend SAP Approuter interprets it using another, leading to a desynchronized state.
4. The attacker's "smuggled" request or parts of it are left in the connection buffer on the backend server, where it gets prepended to subsequent legitimate user requests.
5. This can result in the attacker intercepting and exfiltrating sensitive data contained in responses intended for legitimate users.
6. Alternatively, the desynchronization and malformed requests can cause the Approuter to encounter errors, deplete resources, or crash.
7. This leads to the SAP Approuter application becoming unresponsive and unavailable to legitimate users, resulting in a denial of service.

## Impact

The successful exploitation of CVE-2026-27690 can have severe consequences for organizations utilizing SAP Approuter. Attackers can gain unauthorized access to sensitive user data, including session tokens, credentials, or other confidential information transmitted through the application. This directly compromises the confidentiality of user interactions. Additionally, the vulnerability can be weaponized to perform denial-of-service attacks, making the SAP Approuter application inaccessible to legitimate users. This impacts business operations, disrupts critical processes, and can lead to significant financial and reputational damage.

## Recommendation

* Prioritize patching SAP Approuter instances to mitigate CVE-2026-27690 immediately. Apply the update referenced in the SAP security notes mentioned below to ensure SAP Approuter Node.js package versions are 20.10.0 or higher.
* Regularly consult SAP's security patch day advisories via the `https://url.sap/sapsecuritypatchday` reference to stay informed about critical updates.
