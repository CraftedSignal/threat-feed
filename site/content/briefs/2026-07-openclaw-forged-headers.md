---
title: OpenClaw Vulnerability Allows Local Forged Identity Headers
slug: 2026-07-openclaw-forged-headers
description: A vulnerability (GHSA-rggc-m335-3wvj) in OpenClaw's trusted-proxy deployments allows a local attacker on the same host to forge identity headers, bypassing intended security controls and potentially leading to unauthorized access or privilege escalation if the affected feature is enabled and reachable.
date: "2026-07-03T12:17:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - proxy
  - privilege-escalation
  - defense-evasion
  - npm
  - server
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.18)
  - npm/openclaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: a local same-host caller that can reach the proxy-facing Gateway port could supply identity headers normally reserved for the trusted proxy.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: this could receive operator identity associated with the forged headers. Practical impact depends on the operator's configuration and whether lower-trust input can reach that path.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rggc-m335-3wvj
---

A significant security vulnerability, tracked as GHSA-rggc-m335-3wvj, has been identified in OpenClaw's trusted-proxy deployments, specifically impacting versions prior to `2026.5.18`. This flaw allows a local attacker, operating from the same host where an OpenClaw Gateway instance is running, to forge identity headers. By directly communicating with the proxy-facing Gateway port and presenting these falsified headers, the attacker can effectively bypass the security mechanisms designed for trusted proxies. If the affected feature is active and accessible, this enables the local caller to assume an operator's identity, potentially leading to unauthorized access, configuration changes, or privilege escalation within the OpenClaw environment. This vulnerability is critical for organizations deploying OpenClaw in shared-host or multi-tenant environments where local access by lower-trust processes is possible.

## Attack Chain

1.  **Initial Access**: An attacker gains local access to a system hosting an OpenClaw Gateway instance configured for trusted-proxy deployments. This could be via another compromised application or a low-privilege user account.
2.  **Discovery**: The attacker probes the local system to identify the specific network port on which the OpenClaw Gateway's proxy-facing service is listening.
3.  **Direct Connection**: The attacker establishes a direct network connection from their local process to the discovered OpenClaw Gateway port, bypassing the legitimate trusted proxy infrastructure.
4.  **Header Forgery**: The attacker crafts and sends HTTP requests containing forged identity headers, mimicking those that would normally be generated and supplied by a trusted upstream proxy.
5.  **Vulnerable Processing**: The affected OpenClaw Gateway instance (versions `< 2026.5.18`) accepts and processes these forged identity headers from the direct local connection without proper validation.
6.  **Identity Assumption**: The Gateway attributes the operator identity specified in the forged headers to the local attacker's process.
7.  **Privilege Escalation / Unauthorized Actions**: The attacker, now operating with the assumed operator identity, performs unauthorized actions such as modifying configurations, accessing sensitive data, or escalating privileges within the OpenClaw system.

## Impact

The successful exploitation of this vulnerability can lead to significant security breaches. If an attacker can successfully forge identity headers, they can impersonate an authorized operator within the OpenClaw environment. The practical impact is highly dependent on the privileges associated with the impersonated operator and the specific configurations of the OpenClaw Gateway. This could result in unauthorized configuration changes, data manipulation or exfiltration, or complete administrative control over the OpenClaw instance. Organizations with shared hosting environments or those running multiple applications on the same server as OpenClaw are particularly at risk, as any compromised local process could leverage this flaw.

## Recommendation

*   **Patch Immediately**: Upgrade all OpenClaw Gateway instances to version `2026.5.18` or newer to remediate the vulnerability described in GHSA-rggc-m335-3wvj.
*   **Network Segmentation**: Implement network controls to bind the trusted-proxy ingress behind the actual trusted proxy and firewall direct same-host access to the Gateway port, as mentioned in the GHSA-rggc-m335-3wvj mitigations.
*   **Feature Disablement**: Disable the affected trusted-proxy feature if it is not explicitly required for your operational workflow to reduce the attack surface.
*   **Access Control**: Ensure that lower-trust applications or users on the same host cannot reach the OpenClaw Gateway's proxy-facing port, following the hardening advice from GHSA-rggc-m335-3wvj.
