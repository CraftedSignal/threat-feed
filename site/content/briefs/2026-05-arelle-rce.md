---
title: Arelle Unauthenticated Remote Code Execution Vulnerability
slug: 2026-05-arelle-rce
description: Arelle before 2.39.10 is vulnerable to unauthenticated remote code execution via the /rest/configure REST endpoint, allowing attackers to execute arbitrary Python code by supplying a malicious URL through the plugins parameter.
date: "2026-05-04T18:16:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - arelle
  - vulnerability
vendors:
  - Arelle
products:
  - Arelle
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-42796
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42796
  - https://github.com/Arelle/Arelle/pull/2320
  - https://github.com/Arelle/Arelle/releases/tag/2.39.10
  - https://www.vulncheck.com/advisories/arelle-unauthenticated-rce-via-rest-configure
rules:
  - title: Detect Arelle Plugin Download via REST Endpoint
    description: Detects potential exploitation of the Arelle RCE vulnerability (CVE-2026-42796) by monitoring for requests to the /rest/configure endpoint with a 'plugins' parameter containing a URL.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Arelle Malicious Python Execution
    description: Detects potential execution of malicious Python code downloaded by Arelle via the REST endpoint vulnerability by monitoring for python executions from the Arelle webserver process.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Arelle versions prior to 2.39.10 are susceptible to an unauthenticated remote code execution (RCE) vulnerability. The vulnerability resides in the `/rest/configure` REST endpoint, which improperly handles the `plugins` query parameter. This parameter is forwarded to the plugin manager without proper authentication or authorization checks. An attacker can exploit this flaw by providing a URL pointing to a malicious Python file via the `plugins` parameter. Upon receiving this request, the Arelle webserver downloads and executes the attacker-supplied Python code within the context of the Arelle process. This grants the attacker control over the Arelle server with the same privileges as the Arelle process. This vulnerability poses a significant risk, especially in environments where Arelle servers are exposed to the internet or untrusted networks.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP GET request to the `/rest/configure` endpoint of the Arelle web server.
2. The request includes the `plugins` query parameter, which contains a URL pointing to a malicious Python file hosted on an attacker-controlled server.
3. The Arelle web server receives the request and, without proper authentication or authorization, forwards the `plugins` parameter to the plugin manager.
4. The plugin manager downloads the Python file from the attacker-supplied URL using standard HTTP(S) protocols.
5. The Arelle process executes the downloaded Python code using the Python interpreter.
6. The malicious Python code executes arbitrary commands on the Arelle server, potentially installing malware, creating reverse shells, or exfiltrating sensitive data.
7. The attacker gains control of the Arelle server and can perform further actions, such as accessing internal network resources.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to achieve remote code execution on the Arelle server. This could lead to complete compromise of the server, including sensitive data theft, malware deployment, and further lateral movement within the network. The potential impact includes data breaches, service disruption, and reputational damage. Given the severity and ease of exploitation, any Arelle instance running a version prior to 2.39.10 is at critical risk.

## Recommendation

*   Immediately upgrade Arelle to version 2.39.10 or later to patch CVE-2026-42796.
*   Deploy the Sigma rule "Detect Arelle Plugin Download via REST Endpoint" to identify exploitation attempts targeting the vulnerable `/rest/configure` endpoint.
*   Monitor web server logs for suspicious requests to the `/rest/configure` endpoint containing the `plugins` parameter.
*   Implement network segmentation to limit the potential impact of a compromised Arelle server.
