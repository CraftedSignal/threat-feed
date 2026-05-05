---
title: Cisco ASA Logging Message Suppression
slug: 2024-01-cisco-asa-logging-suppression
description: Detection of 'no logging message' command usage on Cisco ASA devices, potentially indicating an adversary suppressing security-critical log events to evade detection.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - impair-defenses
  - network
vendors:
  - Cisco
  - Splunk
products:
  - ASA
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf
  - https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html
  - https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/monitor-syslog.html#ID-2121-000006da
rules:
  - title: Cisco ASA Logging Message Suppression
    description: Detects the use of the 'no logging message' command on Cisco ASA devices, potentially indicating an attempt to suppress security-critical logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA Specific Logging Message Suppression
    description: Detects the suppression of specific logging messages (111008, 111010) on Cisco ASA devices.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

The "no logging message" command in Cisco ASA devices allows administrators to suppress specific syslog messages, identified by their message ID. Attackers may abuse this functionality to selectively disable logging of events that would otherwise reveal their malicious activity. By suppressing specific message IDs related to authentication failures, configuration changes, or suspicious network activity, attackers can evade detection while allowing normal logging operations to continue, avoiding suspicion that might arise from completely disabling logging. This activity is associated with actors such as LINE-VIPER. This detection focuses on identifying instances where message suppression is configured using message IDs 111008 and 111010.

## Attack Chain

1. An attacker gains unauthorized access to a Cisco ASA device, potentially through stolen credentials or exploiting a vulnerability.
2. The attacker authenticates to the ASA device, gaining privileged EXEC mode access.
3. The attacker executes the "configure terminal" command to enter global configuration mode.
4. The attacker uses the "no logging message <message_id>" command, specifying message IDs related to security events such as authentication failures (e.g., 111008, 111010).
5. The ASA device stops logging events associated with the specified message IDs, preventing security alerts related to those events.
6. The attacker performs malicious activities that would normally trigger these security alerts, knowing that they will not be logged.
7. The attacker exits configuration mode and continues their malicious activity undetected.
8. The attacker maintains persistence to continue evading detection.

## Impact

Successful exploitation allows attackers to operate within a network without triggering security alerts related to their actions on Cisco ASA devices. This can lead to prolonged periods of undetected lateral movement, data exfiltration, or other malicious activities. The suppression of logging messages hinders incident response efforts, making it difficult to investigate and remediate security breaches. The number of potential victims is large given the widespread deployment of Cisco ASA devices.

## Recommendation

*   Deploy the Sigma rule "Cisco ASA Logging Message Suppression" to your SIEM and tune for your environment to detect unauthorized logging suppression.
*   Investigate any instances of logging message suppression, especially those involving security-critical message IDs (authentication, authorization, configuration changes).
*   Correlate detected suppression events with other security alerts to identify potentially compromised ASA devices.
*   Review and enforce strict access controls for Cisco ASA devices to prevent unauthorized configuration changes.
*   Configure Cisco ASA devices to generate and forward message ID 111008 and 111010 as per the documentation to ensure the effectiveness of the provided rule.
*   Establish a baseline of approved suppressed message IDs to identify anomalous configurations, addressing potential false positives as described in the KFP section.
