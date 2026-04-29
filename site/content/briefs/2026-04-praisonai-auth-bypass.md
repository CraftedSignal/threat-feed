---
title: PraisonAI Gateway Unauthenticated Access Vulnerability
slug: 2026-04-praisonai-auth-bypass
description: PraisonAI Gateway server versions prior to 4.5.97 allow unauthenticated access to WebSocket connections and agent topology, enabling unauthorized message sending and agent enumeration.
date: "2026-04-03T23:17:06Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - vulnerability
  - authentication bypass
  - websocket
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-34952
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34952
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-cfh6-vr3j-qc3g
rules:
  - title: Detect Unauthenticated Access to PraisonAI /ws Endpoint
    description: Detects network connections to the PraisonAI Gateway's /ws endpoint, indicating potential unauthenticated access attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.006
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthenticated Access to PraisonAI /info Endpoint
    description: Detects network connections to the PraisonAI Gateway's /info endpoint, indicating potential enumeration of agent topology.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-34952 exposes a critical vulnerability in PraisonAI, a multi-agent teams system. Specifically, versions of the PraisonAI Gateway server prior to 4.5.97 lack authentication for WebSocket connections at the `/ws` endpoint and for serving agent topology information at the `/info` endpoint. This absence of authentication means that any client on the network can connect to these endpoints. Attackers could exploit this vulnerability to enumerate registered agents, send arbitrary messages to agents and their associated tool sets, and potentially gain unauthorized control over the PraisonAI system. The vulnerability was reported on April 3, 2026, and is addressed in version 4.5.97 of PraisonAI.

## Attack Chain

1. An attacker identifies a vulnerable PraisonAI Gateway server running a version prior to 4.5.97.
2. The attacker establishes a WebSocket connection to the `/ws` endpoint of the server without providing any credentials.
3. The server, lacking authentication, accepts the connection.
4. The attacker sends a request to the `/info` endpoint to enumerate registered agents and their topology.
5. The server responds with the agent topology data.
6. The attacker crafts arbitrary messages and sends them to specific agents through the established WebSocket connection.
7. The targeted agent receives the message and executes the corresponding actions, potentially including tool usage or data modification.
8. The attacker achieves unauthorized control over the PraisonAI system by manipulating agents and their tool sets.

## Impact

Successful exploitation of this vulnerability could lead to complete compromise of the PraisonAI system. Attackers can enumerate and control agents, manipulate data, and potentially use the agents' tool sets for malicious purposes, such as data theft or system disruption. This could impact organizations relying on PraisonAI for critical functions, leading to financial losses, reputational damage, and operational downtime. The severity is high due to the ease of exploitation and the potential for widespread damage.

## Recommendation

*   Upgrade all PraisonAI Gateway servers to version 4.5.97 or later to patch CVE-2026-34952.
*   Deploy the Sigma rules provided to detect unauthorized connections to the `/ws` and `/info` endpoints.
*   Monitor network traffic for suspicious WebSocket connections to the PraisonAI Gateway server to detect potential exploitation attempts.
