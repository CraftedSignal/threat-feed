---
title: Axios Library Vulnerable to Cloud Metadata Exfiltration via Header Injection
slug: 2024-01-24-axios-header-injection
description: The Axios library is vulnerable to a header injection chain that allows prototype pollution in a third-party dependency to be escalated into remote code execution or full cloud compromise via AWS IMDSv2 bypass by polluting Object.prototype with CRLF characters to smuggle requests to the AWS Metadata Service.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - crlf-injection
  - prototype-pollution
  - aws-metadata
  - ssrf
vendors:
  - Axios
products:
  - Axios
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Security Software Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://github.com/advisories/GHSA-fvcv-3m26-pcqx
iocs:
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: analytics.internal
ioc_counts:
  domain: 1
  ip: 1
rules:
  - title: Detect Suspicious AWS Metadata Service Access via Header Injection
    description: Detects suspicious network connections to the AWS Metadata Service IP address (169.254.169.254) potentially indicating header injection and IMDSv2 bypass attempts.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Header Injection via CRLF in Process Creation
    description: Detects process creations where the command line contains suspicious CRLF sequences which may indicate a header injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Axios library, a popular HTTP client, is vulnerable to a critical header injection vulnerability (CVE-2026-40175) affecting all versions (v0.x - v1.x) through < 1.15.0. This vulnerability, located in `lib/adapters/http.js`, arises from a lack of HTTP header sanitization, specifically related to CRLF characters. Exploitation leverages a "gadget" attack chain, where prototype pollution in any third-party dependency can be exploited to bypass AWS IMDSv2 and achieve remote code execution or full cloud compromise. The vulnerability requires zero direct user input, making it particularly insidious. An attacker can pollute `Object.prototype` through other vulnerable libraries in the stack (e.g., `qs`, `minimist`, `ini`, `body-parser`), and Axios will inadvertently incorporate the polluted properties during its configuration merge, leading to request smuggling.

## Attack Chain

1.  Attacker identifies a separate dependency with a prototype pollution vulnerability (e.g., via vulnerable query string parsing).
2.  The attacker crafts a request that pollutes `Object.prototype` with a malicious header value containing CRLF characters. For example: `Object.prototype['x-amz-target'] = "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\nGET /ignore";`
3.  The application makes a seemingly benign HTTP request using Axios, such as `axios.get('https://analytics.internal/pings')`.
4.  Axios merges the polluted `x-amz-target` property into the request headers without proper sanitization.
5.  Axios writes the unsanitized header value directly to the socket, resulting in a smuggled HTTP request.
6.  The smuggled request targets the AWS Metadata Service (169.254.169.254) to obtain an IMDSv2 session token. The attacker includes the necessary `X-aws-ec2-metadata-token-ttl-seconds` header, bypassing typical SSRF protections.
7.  The Metadata Service returns a session token to the attacker.
8.  Using the stolen session token, the attacker can then steal IAM credentials associated with the instance, leading to full cloud account compromise.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass AWS IMDSv2 session tokens, a key security control designed to prevent SSRF attacks. This can lead to the theft of AWS IAM credentials and complete compromise of the cloud environment. The vulnerability can also be leveraged for authentication bypass by injecting malicious headers like `Cookie` or `Authorization`, allowing attackers to pivot into internal administrative panels. Cache poisoning attacks are also possible via `Host` header injection.

## Recommendation

*   Apply the patch suggested in the advisory to `lib/adapters/http.js` (and `xhr.js`), which validates header values for CRLF characters, preventing request smuggling.
*   Deploy the Sigma rule "Detect Suspicious AWS Metadata Service Access via Header Injection" to your SIEM, tuning it for your environment.
*   Monitor network connections to the AWS Metadata Service IP (169.254.169.254), especially from unusual processes.
*   Review third-party dependencies for known prototype pollution vulnerabilities to prevent the initial pollution that triggers the Axios gadget.
