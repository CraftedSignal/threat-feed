---
title: Tmds.DBus Vulnerability Allows Signal Spoofing and Resource Exhaustion
slug: 2026-04-tmds-dbus-vuln
description: Tmds.DBus and Tmds.DBus.Protocol are vulnerable to signal spoofing, resource exhaustion, and application crashes due to malformed messages from malicious D-Bus peers on the same bus.
date: "2026-04-09T17:16:30Z"
severities:
  - high
tags:
  - dbus
  - vulnerability
  - dotnet
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-39959
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39959
rules:
  - title: Detect Excessive File Descriptors in D-Bus Messages
    description: Detects D-Bus messages with an unusually high number of file descriptors, potentially indicating a resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1499.001
    data_sources:
      - application
      - linux
  - title: Detect D-Bus Message Body Parsing Errors
    description: Detects application logs indicating errors while parsing D-Bus message bodies, which may indicate a malformed message attack.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    data_sources:
      - application
      - linux
rules_count: 2
---

Tmds.DBus is a .NET library used for interacting with the D-Bus inter-process communication system. A vulnerability exists in versions prior to 0.92.0 for Tmds.DBus and 0.92.0 and 0.21.3 for Tmds.DBus.Protocol, allowing a malicious D-Bus peer on the same bus to perform several malicious actions. These include spoofing signals by impersonating the owner of a well-known name, exhausting system resources by sending messages with an excessive number of Unix file descriptors, and crashing the…
