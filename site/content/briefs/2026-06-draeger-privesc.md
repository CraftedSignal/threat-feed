---
title: 'CVE-2019-25718: Dräger Infinity Explorer C700 Kiosk Escape Vulnerability'
slug: 2026-06-draeger-privesc
description: Dräger Infinity Explorer C700 contains a privilege escalation vulnerability (CVE-2019-25718) that allows attackers to break out of kiosk mode, access the underlying operating system, and potentially cause the device to display incorrect patient monitor information.
date: "2026-06-01T23:16:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - cve-2019-25718
  - kiosk escape
  - medical device
vendors:
  - Dräger
products:
  - Infinity Explorer C700
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2019-25718
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25718
rules:
  - title: Detect Unusual Process Execution from Medical Device
    description: Detects unusual process execution from medical device - likely a kiosk escape attempt or post exploitation activity
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Network Connection from Medical Device
    description: Detects unusual network connections from medical devices after a potential kiosk escape
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

Dräger Infinity Explorer C700 is vulnerable to a privilege escalation (CVE-2019-25718) stemming from a flaw in the kiosk mode implementation. An attacker can exploit this vulnerability via a specific dialog interaction to escape the kiosk environment and gain access to the underlying operating system. This access can then be leveraged to manipulate the device, potentially leading to the display of incorrect or no information from the connected Delta Family patient monitor. The vulnerability allows an attacker to gain control of the operating system, which impacts the integrity of displayed medical data.

## Attack Chain

1.  The attacker gains physical or remote access to a Dräger Infinity Explorer C700 device.
2.  The attacker interacts with a specific dialog within the kiosk mode application.
3.  Through a series of interactions (details unspecified in source), the attacker triggers the privilege escalation vulnerability (CVE-2019-25718).
4.  The attacker successfully escapes the kiosk mode environment.
5.  The attacker gains access to the underlying operating system.
6.  The attacker uses the elevated privileges to modify system settings or install malicious software.
7.  The attacker manipulates the data displayed by the device from the connected Delta Family patient monitor.
8.  The device displays incorrect, or no information to medical personnel.

## Impact

Successful exploitation of CVE-2019-25718 allows an attacker to break out of kiosk mode on a Dräger Infinity Explorer C700 device, gaining access to the underlying operating system. This could lead to the display of incorrect or missing information from the connected Delta Family patient monitor, potentially affecting patient care and safety. The number of affected devices or specific sectors targeted is not specified in the provided source.

## Recommendation

*   Implement strict physical access controls to the Dräger Infinity Explorer C700 devices to prevent unauthorized access and initial exploitation.
*   Monitor process creations for unusual processes running outside of the expected kiosk application scope.
*   Monitor network connections for suspicious outbound traffic originating from the Dräger Infinity Explorer C700 devices using the Sigma rule "Detect Unusual Network Connection from Medical Device".
