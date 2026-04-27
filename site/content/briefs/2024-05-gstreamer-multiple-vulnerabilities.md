---
title: GStreamer Multiple Vulnerabilities Allow for Remote Code Execution and Denial of Service
slug: 2024-05-gstreamer-multiple-vulnerabilities
description: Multiple vulnerabilities in GStreamer allow a remote, anonymous attacker to cause a denial-of-service condition or execute arbitrary code.
date: "2024-05-03T12:00:00Z"
severities:
  - critical
tags:
  - gstreamer
  - vulnerability
  - denial-of-service
  - remote-code-execution
vendors:
  - GStreamer
products:
  - GStreamer
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2881
rules:
  - title: Detect Suspicious Process Creation by GStreamer
    description: Detects suspicious child processes spawned by GStreamer, which may indicate exploitation leading to code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Connection from GStreamer to External IP
    description: Detects GStreamer processes initiating outbound network connections to external IPs, which may indicate command and control activity after exploitation.
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

GStreamer is a widely used open-source multimedia framework. A recent advisory highlights the existence of multiple vulnerabilities within GStreamer that could be exploited by a remote, anonymous attacker. Successful exploitation of these vulnerabilities could lead to a denial-of-service (DoS) condition, rendering the affected system or application unavailable, or, more critically, the execution of arbitrary code, potentially granting the attacker full control over the compromised system. While…
