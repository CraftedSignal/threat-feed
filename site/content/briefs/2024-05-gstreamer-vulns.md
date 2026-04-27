---
title: GStreamer Multiple Vulnerabilities Allow Remote Code Execution and Denial of Service
slug: 2024-05-gstreamer-vulns
description: Multiple vulnerabilities in GStreamer could be exploited by a remote, anonymous attacker to execute arbitrary code or cause a denial of service condition.
date: "2024-05-03T12:00:00Z"
severities:
  - critical
tags:
  - gstreamer
  - rce
  - dos
vendors:
  - GStreamer
products:
  - GStreamer
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2401
rules:
  - title: Detect Suspicious GStreamer Process Execution
    description: Detects potentially malicious processes spawned by GStreamer.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Activity by GStreamer
    description: Detects suspicious network activity associated with GStreamer processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

GStreamer is a widely used open-source multimedia framework. According to the BSI advisory, multiple unspecified vulnerabilities exist within GStreamer that could allow a remote, anonymous attacker to execute arbitrary code or cause a denial of service (DoS). The lack of specific CVEs or technical details makes it difficult to determine the exact attack vectors, but the potential impact necessitates immediate attention from security teams. Given its widespread use in media players, streaming…
