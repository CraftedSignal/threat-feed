---
title: Detection of Suspicious Cisco Configuration Changes via Archive Logging
slug: 2024-01-cisco-config-changes
description: This analytic detects suspicious configuration changes on Cisco devices by analyzing archive logs for activities such as backdoor account creation, SNMP community string modifications, and TFTP server configurations, potentially indicating attacker presence and lateral movement.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Static Tundra
tags:
  - cisco
  - network-security
  - configuration-change
vendors:
  - Cisco
  - Splunk
products:
  - IOS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2018-0171
    cvss: 9.8
    epss: 0.92675
references:
  - https://blog.talosintelligence.com/static-tundra/
  - https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2
  - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/15-mt/config-mgmt-15-mt-book/cm-config-logger.html
rules:
  - title: Cisco Privilege Escalation via Configuration Change
    description: Detects the creation of a new user account with privilege level 15 on a Cisco device, indicating a potential backdoor account.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - firewall
      - cisco
  - title: Cisco SNMP Community String Modification
    description: Detects modifications to SNMP community strings on Cisco devices, which could indicate unauthorized access to network monitoring data.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - firewall
      - cisco
  - title: Cisco TFTP Server Configuration
    description: Detects configuration of a TFTP server on a Cisco device, potentially used for data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1505.003
    data_sources:
      - firewall
      - cisco
rules_count: 3
---

This threat brief focuses on detecting malicious activity within Cisco IOS devices by analyzing configuration archive logs. Configuration archive logging captures all modifications made to a device's configuration, offering a detailed audit trail. Analyzing these logs allows for the identification of suspicious or malicious activities, such as the creation of backdoor accounts, modifications to SNMP community strings, and the setup of TFTP servers for potential data exfiltration. This detection method is crucial for identifying advanced attack campaigns, exemplified by threat actors like Static Tundra, who often manipulate network configurations to maintain persistence and facilitate lateral movement. The monitoring of configuration changes across different user sessions provides a comprehensive view of device activity.

## Attack Chain

1.  Attacker gains initial access to the network through an external vulnerability or compromised credentials.
2.  Attacker leverages their initial access to authenticate to a Cisco IOS device.
3.  The attacker modifies the device configuration to create a new user account with privilege level 15, effectively creating a backdoor.
4.  The attacker changes the SNMP community string to gain unauthorized access to network monitoring data.
5.  The attacker configures a TFTP server on the Cisco device to enable data exfiltration.
6.  The attacker modifies the user table to elevate privileges of existing accounts.
7.  The attacker uses the elevated privileges to move laterally within the network.
8.  The attacker exfiltrates sensitive data using the configured TFTP server.

## Impact

Compromised Cisco IOS devices can lead to significant network breaches, data exfiltration, and persistent access for malicious actors. Successful exploitation allows attackers to move laterally within the network, gain access to sensitive data, and maintain a foothold for future attacks. The CVE-2018-0171 vulnerability, related to Cisco Smart Install, can allow remote code execution, potentially impacting thousands of devices if not properly patched. Unauthorized configuration changes can disrupt network operations, compromise sensitive data, and damage an organization's reputation.

## Recommendation

*   Enable Cisco IOS archive logging with the commands `archive` and `log config` in global configuration mode to generate the necessary logs for detection.
*   Configure command logging with `archive log config logging enable` and set appropriate logging levels with `logging trap informational` on Cisco devices to capture configuration changes.
*   Deploy the Sigma rule "Cisco Privilege Escalation via Configuration Change" to detect the creation of high-privilege accounts (All_Changes.command="*username*privilege 15*").
*   Deploy the Sigma rule "Cisco SNMP Community String Modification" to identify unauthorized changes to SNMP settings (All_Changes.command="*snmp-server community*").
*   Investigate any alerts generated by the Sigma rules, focusing on the source device (`dest`) and the user (`user`) involved, using the provided drilldown searches.
*   Monitor logs for CVE-2018-0171 and apply necessary patches.
