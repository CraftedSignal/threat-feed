---
title: Cisco ASA Logging Message Suppression
slug: 2024-01-03-cisco-asa-logging-suppression
description: Adversaries may suppress specific log message IDs on Cisco ASA devices using the 'no logging message' command to selectively disable logging of security-critical events and evade detection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cisco-asa
  - logging
  - defense-evasion
  - network
vendors:
  - Cisco
products:
  - Cisco ASA
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/cisco_asa___logging_message_suppression.yml
  - https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html
  - https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/monitor-syslog.html#ID-2121-000006da
  - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf
rules:
  - title: Cisco ASA Logging Message Suppression Detected
    description: Detects the use of 'no logging message' command on Cisco ASA devices to suppress specific log messages.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA Logging Configuration Change
    description: Detects a configuration change event with specific message IDs.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1070
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This detection focuses on identifying the suppression of logging messages within Cisco ASA devices, a tactic used by adversaries to evade detection. Attackers leverage the "no logging message" command to selectively disable the logging of specific, security-critical events, such as authentication failures, configuration changes, or suspicious network activity. This approach allows them to maintain a degree of stealth while still allowing other logging functions to proceed normally, avoiding suspicion that might be raised by a complete disabling of logging. The detection specifically monitors for the execution of commands with message IDs 111008 and 111010 that include the "no logging message" command, which can suppress message IDs irrespective of the configured severity level. Identifying unauthorized or suspicious use of this command is crucial for maintaining auditability and detecting malicious activity within the network environment.

## Attack Chain

1.  The attacker gains unauthorized access to a Cisco ASA device, potentially through stolen credentials or exploiting a vulnerability.
2.  The attacker executes the command `enable` to enter privileged EXEC mode.
3.  The attacker then enters global configuration mode using the `configure terminal` command.
4.  The attacker identifies security-critical message IDs, such as those related to authentication failures or configuration changes.
5.  The attacker uses the `no logging message <message_id>` command to suppress logging for these specific message IDs. For example, `no logging message 111008`.
6.  The ASA device ceases to log events associated with the suppressed message IDs, effectively hiding the attacker's actions.
7.  The attacker performs malicious actions on the network, knowing that these actions will not be logged.
8.  The attacker exits configuration mode and privileged EXEC mode, leaving the ASA device with suppressed logging.

## Impact

Successful suppression of logging messages can severely hinder incident response and forensic investigations. If critical security events are not logged, administrators will be unaware of malicious activities occurring on the network. This can lead to delayed detection of breaches, data exfiltration, or other significant security incidents. The NCSC report referenced in the related articles details the use of similar techniques by advanced persistent threat (APT) groups to maintain persistence and evade detection on compromised systems, which highlights the potential impact of this tactic.

## Recommendation

*   Enable Cisco ASA syslog data ingestion into your SIEM using the Cisco Security Cloud TA, as required by the detection [How To Implement].
*   Configure Cisco ASA devices to generate and forward message IDs 111008 and 111010, or adjust the logging level to include these messages if needed [How To Implement].
*   Deploy the Sigma rule "Cisco ASA Logging Message Suppression Detected" to identify instances of logging message suppression [rules].
*   Investigate any detected instances of message suppression, focusing on unauthorized suppressions of security-critical message IDs, suppressions by non-administrative accounts, and suppressions occurring during unusual hours [description].
*   Establish a baseline of approved suppressed message IDs and monitor for deviations from this baseline [known_false_positives].
