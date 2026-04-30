---
title: Tmds.DBus Vulnerability Allows Signal Spoofing and Resource Exhaustion
slug: 2026-04-tmds-dbus-vuln
description: Tmds.DBus and Tmds.DBus.Protocol are vulnerable to signal spoofing, resource exhaustion, and application crashes due to malformed messages from malicious D-Bus peers on the same bus.
date: "2026-04-09T17:16:30Z"
type: advisory
types:
  - advisory
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

Tmds.DBus is a .NET library used for interacting with the D-Bus inter-process communication system. A vulnerability exists in versions prior to 0.92.0 for Tmds.DBus and 0.92.0 and 0.21.3 for Tmds.DBus.Protocol, allowing a malicious D-Bus peer on the same bus to perform several malicious actions. These include spoofing signals by impersonating the owner of a well-known name, exhausting system resources by sending messages with an excessive number of Unix file descriptors, and crashing the application by sending malformed message bodies that cause unhandled exceptions on the SynchronizationContext. This vulnerability could lead to denial of service or potentially allow for further exploitation within the affected application's context. Defenders need to ensure they are running patched versions of this software.

## Attack Chain

1.  A malicious actor gains access to the same D-Bus instance as the target application.
2.  The attacker identifies a well-known name that the target application utilizes.
3.  The attacker crafts a malicious D-Bus message designed to impersonate the owner of the well-known name.
4.  The attacker sends this spoofed signal to the target application through the D-Bus.
5.  Alternatively, the attacker crafts a D-Bus message with an excessive number of Unix file descriptors.
6.  The attacker sends the resource-intensive message, attempting to exhaust system resources.
7.  Or the attacker crafts a malformed message body designed to cause an unhandled exception.
8.  Successful exploitation leads to signal spoofing, resource exhaustion, or application crash, potentially leading to denial of service.

## Impact

Successful exploitation of this vulnerability allows a malicious actor to disrupt services that rely on Tmds.DBus. By spoofing signals, an attacker can manipulate the behavior of applications. By exhausting system resources or crashing applications, the attacker can cause denial of service. While the specific number of victims or sectors affected is not detailed, the potential impact is significant for systems using vulnerable versions of Tmds.DBus.

## Recommendation

*   Upgrade Tmds.DBus to version 0.92.0 or later and Tmds.DBus.Protocol to version 0.92.0 or 0.21.3 or later to remediate CVE-2026-39959.
*   Monitor D-Bus traffic for suspicious patterns, such as messages with excessive file descriptors, by creating custom monitoring tools.
*   Implement application-level validation of D-Bus messages to prevent exploitation through malformed message bodies.
