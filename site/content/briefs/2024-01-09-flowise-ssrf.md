---
title: FlowiseAI API Chain SSRF Vulnerability
slug: 2024-01-09-flowise-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability exists in FlowiseAI's POST/GET API Chain components, allowing unauthenticated attackers to force the server to make arbitrary HTTP requests to internal and external systems by injecting malicious prompt templates.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - flowiseai
  - prompt-injection
  - vulnerability
vendors:
  - FlowiseAI
products:
  - FlowiseAI
  - npm/flowise
  - npm/flowise-components
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
references:
  - https://github.com/advisories/GHSA-6r77-hqx7-7vw8
iocs:
  - type: url
    value: http://host.docker.internal:8080/flag
  - type: url
    value: http://internal-api.company.local
ioc_counts:
  url: 2
rules:
  - title: FlowiseAI Suspicious Internal Network Connection
    description: Detects FlowiseAI servers making connections to internal IP ranges, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - windows
  - title: FlowiseAI Malicious API URL Request
    description: Detects FlowiseAI making a request to malicious API URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FlowiseAI, a low-code open-source platform for building custom LLM flows, is vulnerable to Server-Side Request Forgery (SSRF) in its POST/GET API Chain components. This vulnerability, affecting versions 3.0.13 and earlier, allows unauthenticated attackers to inject malicious prompt templates into the API documentation, causing the FlowiseAI server to make arbitrary HTTP requests to internal and external systems. The root cause is the lack of validation when constructing URLs and request parameters from LLM responses. Attackers can exploit this by providing fake API documentation that redirects requests to sensitive internal services, enabling internal network reconnaissance, credential access, and data exfiltration. This vulnerability poses a significant risk as it allows attackers to bypass intended API constraints and potentially gain unauthorized access to internal resources.

## Attack Chain

1.  The attacker crafts a malicious prompt containing a manipulated API documentation section.
2.  This malicious prompt is injected into the FlowiseAI API Chain component via user-controlled input.
3.  The API Chain component uses an LLM to generate a URL and data parameters based on the injected API documentation.
4.  Due to lack of validation, the system constructs an HTTP request using the attacker-controlled URL and data.
5.  The FlowiseAI server executes the HTTP request to the attacker-specified internal or external endpoint using the `fetch` function in `postCore.ts`.
6.  The attacker gains the ability to interact with internal APIs, cloud metadata endpoints, or other sensitive resources that trust the FlowiseAI server.
7.  The attacker scans internal network services to identify running applications and open ports.
8.  The attacker exfiltrates sensitive data obtained from internal services or cloud metadata.

## Impact

The SSRF vulnerability allows unauthenticated attackers to abuse the FlowiseAI server as a proxy, leading to internal network reconnaissance, access to cloud metadata, exploitation of internal services, and potential data exfiltration. A successful attack can compromise sensitive internal data, bypass firewall rules, and allow attackers to pivot to other internal resources. Affected packages include `npm/flowise` and `npm/flowise-components` with versions 3.0.13 and earlier. This vulnerability enables attackers to scan internal network services and potentially access cloud metadata endpoints to retrieve credentials.

## Recommendation

*   Apply patches or upgrade to versions later than 3.0.13 for `npm/flowise` and `npm/flowise-components` to remediate the SSRF vulnerability.
*   Deploy the Sigma rule "FlowiseAI Suspicious Internal Network Connection" to detect unauthorized connections to internal networks originating from FlowiseAI servers.
*   Monitor network traffic originating from FlowiseAI servers for connections to internal IP ranges or sensitive internal services, based on the IOCs provided.
*   Implement strict input validation and sanitization for user-provided API documentation to prevent prompt injection attacks.
