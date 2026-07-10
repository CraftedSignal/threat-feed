---
title: 'Tmds.DBus Vulnerability: Signal Spoofing and Denial of Service'
slug: 2024-01-tmds-dbus-spoofing-dos
description: Tmds.DBus and Tmds.DBus.Protocol libraries are vulnerable to signal spoofing, resource exhaustion, and denial-of-service attacks by malicious D-Bus peers, allowing impersonation, resource depletion via excessive file descriptors, and application crashes via malformed messages.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dbus
  - denial-of-service
  - spoofing
vendors:
  - Tmds
products:
  - Tmds.DBus
  - Tmds.DBus.Protocol
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-xrw6-gwf8-vvr9
rules:
  - title: Detect Excessive File Descriptors in D-Bus Messages
    description: Detects D-Bus messages with a large number of Unix file descriptors, potentially indicating a resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
      - resource_development
    data_sources:
      - network_connection
      - linux
  - title: Detect Potential D-Bus Signal Spoofing
    description: Detects potential D-Bus signal spoofing attempts by monitoring for messages claiming to originate from a well-known name but lacking proper authentication (requires D-Bus audit logging or similar).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - denial_of_service
    data_sources:
      - application
      - linux
  - title: Detect D-Bus Application Crashes
    description: Detects application crashes potentially caused by malformed D-Bus messages. Requires application-level logging.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    data_sources:
      - application
      - linux
rules_count: 3
---

The Tmds.DBus and Tmds.DBus.Protocol libraries, utilized in .NET applications for inter-process communication, are susceptible to attacks from malicious D-Bus peers within the same bus. This vulnerability allows an attacker to spoof signals by impersonating the owner of a well-known name, potentially leading to unauthorized actions or information disclosure. Additionally, attackers can exhaust system resources by flooding the target with messages containing an excessive number of Unix file descriptors, or trigger application crashes by transmitting malformed message bodies that cause unhandled exceptions. These vulnerabilities affect versions prior to 0.92.0 of Tmds.DBus and versions prior to 0.21.3 (or between 0.22.0 and 0.92.0) of Tmds.DBus.Protocol, posing a significant risk to applications relying on these libraries for secure and reliable communication. Defenders should prioritize upgrading to the patched versions to mitigate these risks.

## Attack Chain

1.  **Initial Access:** A malicious actor gains access to the same D-Bus instance as the target application. This could be achieved through compromising a separate process on the same system.
2.  **Name Enumeration:** The attacker enumerates available well-known names on the D-Bus to identify potential targets for impersonation.
3.  **Signal Spoofing:** The attacker crafts a D-Bus message that spoofs a signal originating from the owner of a well-known name, taking advantage of the vulnerability in Tmds.DBus to bypass authentication.
4.  **Resource Exhaustion:** The attacker sends a series of D-Bus messages to the target application, each containing a large number of Unix file descriptors.
5.  **File Descriptor Spillover:** The target application attempts to process the messages, leading to an excessive consumption of file descriptors.
6.  **Denial of Service (Resource):** The exhaustion of file descriptors prevents the target application from handling legitimate requests, leading to a denial-of-service condition.
7.  **Application Crash:** Alternatively, the attacker sends a D-Bus message with a malformed message body specifically crafted to trigger an unhandled exception in the target application's SynchronizationContext.
8.  **Denial of Service (Crash):** The unhandled exception causes the target application to crash, resulting in a denial-of-service condition.

## Impact

Successful exploitation can lead to a range of consequences, including unauthorized actions performed under the guise of a legitimate service, resource exhaustion causing system instability, and application crashes leading to service outages. The number of victims depends on the number of applications utilizing vulnerable versions of Tmds.DBus and Tmds.DBus.Protocol on a shared D-Bus instance. The impact is particularly severe in environments where D-Bus is used for critical inter-process communication, such as system services and desktop environments.

## Recommendation

*   Upgrade Tmds.DBus to version 0.92.0 or later to address the signal spoofing, resource exhaustion, and denial-of-service vulnerabilities.
*   Upgrade Tmds.DBus.Protocol to version 0.21.3 or later or version 0.92.0 or later to address the signal spoofing, resource exhaustion, and denial-of-service vulnerabilities.
*   Monitor D-Bus traffic for suspicious messages containing an unusually large number of Unix file descriptors using a network monitoring tool with visibility into D-Bus protocols. Consider developing a custom rule for this.
