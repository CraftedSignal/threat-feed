---
title: PraisonAI Gateway Unauthenticated Access Vulnerability
slug: 2026-04-praisonai-auth-bypass
description: PraisonAI Gateway server versions prior to 4.5.97 allow unauthenticated access to WebSocket connections and agent topology, enabling unauthorized message sending and agent enumeration.
date: "2026-04-03T23:17:06Z"
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

CVE-2026-34952 exposes a critical vulnerability in PraisonAI, a multi-agent teams system. Specifically, versions of the PraisonAI Gateway server prior to 4.5.97 lack authentication for WebSocket connections at the `/ws` endpoint and for serving agent topology information at the `/info` endpoint. This absence of authentication means that any client on the network can connect to these endpoints. Attackers could exploit this vulnerability to enumerate registered agents, send arbitrary messages to…
