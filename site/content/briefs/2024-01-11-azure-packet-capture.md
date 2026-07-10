---
title: Azure VNet Full Network Packet Capture Enabled
slug: 2024-01-11-azure-packet-capture
description: Detection of Azure Network Watcher's Packet Capture feature being enabled, potentially indicating malicious network sniffing for credential access and discovery of sensitive data in unencrypted traffic.
date: "2024-01-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - network-sniffing
  - credential-access
vendors:
  - Microsoft
products:
  - Azure
  - Azure Network Watcher
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
  - https://attack.mitre.org/techniques/T1040/
  - https://attack.mitre.org/tactics/TA0006/
  - https://attack.mitre.org/tactics/TA0007/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_network_full_network_packet_capture_detected.toml
rules:
  - title: Azure Network Watcher Packet Capture Started
    description: Detects the start of a network packet capture in Azure using Network Watcher, which could indicate potential network sniffing activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1040
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure VPN Connection Packet Capture Started
    description: Detects the start of a network packet capture on a VPN connection in Azure using Network Watcher, which could indicate potential network sniffing activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1040
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Network Packet Capture Write Event
    description: Detects a network packet capture write event in Azure using Network Watcher, indicating potential network sniffing activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1040
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 3
---

The Azure Network Watcher Packet Capture feature is designed for legitimate network traffic inspection and troubleshooting. However, malicious actors can abuse this feature to perform network sniffing and capture sensitive data, including credentials, from unencrypted internal traffic within Azure Virtual Networks (VNets). This can lead to unauthorized access to systems and data. The detection rule focuses on identifying instances where packet capture is initiated successfully, providing an opportunity to detect and respond to potential credential access attempts. The rule leverages Azure activity logs to monitor for specific packet capture operations, ensuring that suspicious activity is flagged for investigation. The scope of this threat is limited to Azure environments that utilize Network Watcher and have not implemented proper network segmentation or encryption.

## Attack Chain

1.  **Initial Access:** An attacker gains access to an Azure account with sufficient privileges to manage Network Watcher and initiate packet captures.
2.  **Discovery:** The attacker uses the compromised account to explore the Azure environment, identifying target VNets and subnets containing potentially valuable data.
3.  **Packet Capture Configuration:** The attacker configures the Network Watcher Packet Capture feature to capture traffic from the targeted VNet or subnet. This involves specifying the target VM or network interface and the duration of the capture.
4.  **Start Packet Capture:** The attacker initiates the packet capture process, which begins recording network traffic based on the configured parameters. The `MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION` operation is triggered in the Azure activity logs.
5.  **Data Acquisition:** Network traffic, including unencrypted credentials or sensitive data, is captured and stored in a designated storage account.
6.  **Data Exfiltration (Potential):** If the attacker has configured the packet capture to store data outside the secure environment, they may exfiltrate the captured data for further analysis or malicious use.
7.  **Credential Access:** The attacker analyzes the captured network traffic to identify and extract credentials or other sensitive information.
8.  **Lateral Movement/Privilege Escalation:** Using the acquired credentials, the attacker attempts to move laterally within the Azure environment, gaining access to additional systems and resources, or escalate privileges to gain higher-level control.

## Impact

Successful exploitation could lead to the compromise of sensitive data, including user credentials, API keys, and proprietary information. The impact could range from unauthorized access to internal systems and data breaches to complete control over the affected Azure resources. The severity depends on the scope of the captured network traffic and the sensitivity of the data transmitted. Organizations in all sectors utilizing Azure are potentially vulnerable. The number of victims can vary depending on the access level of the compromised account and the targeted resources.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect malicious packet capture activity in Azure.
*   Review Azure activity logs for instances of `MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION`, `MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION`, or `MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE` operations with a Success outcome, as identified in the rule query.
*   Implement the recommendations for Response and Remediation provided in the Setup section of the referenced Elastic rule to improve detection and response capabilities.
*   Regularly audit Azure user roles and permissions to ensure that only authorized personnel have the ability to manage Network Watcher and initiate packet captures.
