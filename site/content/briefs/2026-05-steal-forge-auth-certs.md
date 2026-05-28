---
title: Steal or Forge Authentication Certificates Behavior Identified
slug: 2026-05-steal-forge-auth-certs
description: The analytic identifies potential threats related to the theft or forgery of authentication certificates by detecting when five or more analytics from the Windows Certificate Services story trigger within a specified timeframe, indicating an ongoing attack aimed at compromising authentication mechanisms that could grant unauthorized access to sensitive systems and data.
date: "2026-05-28T17:46:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - t1649
  - endpoint
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
references:
  - https://research.splunk.com/stories/windows_certificate_services/
  - https://attack.mitre.org/techniques/T1649/
rules:
  - title: Steal or Forge Authentication Certificates Behavior Identified - Splunk Correlation
    description: Detects potential certificate theft or forgery by correlating multiple alerts from the Windows Certificate Services story in Splunk.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1649
    data_sources:
      - datamodel
      - splunk
rules_count: 1
---

This analytic identifies potential threats related to the theft or forgery of authentication certificates. It leverages the Splunk Risk data model to detect when five or more analytics from the "Windows Certificate Services" analytic story trigger within a specified timeframe. This aggregation of risk scores and event counts from multiple detections within the Windows Certificate Services story indicates a potential attack aimed at compromising authentication mechanisms. Attackers could gain unauthorized access to sensitive systems and data, leading to severe security breaches. This detection is designed to identify ongoing attacks, rather than individual certificate-related events, by correlating multiple alerts related to certificate services.

## Attack Chain

1. Initial compromise: An attacker gains initial access to a system within the target environment.
2. Reconnaissance: The attacker performs reconnaissance on the target network to identify systems running Windows Certificate Services.
3. Vulnerability exploitation: The attacker exploits vulnerabilities within the Certificate Services, potentially including stealing or forging certificates.
4. Certificate theft/forgery: The attacker steals existing valid certificates or forges new certificates to impersonate legitimate users or systems.
5. Lateral movement: Using the stolen or forged certificates, the attacker moves laterally to other systems within the network.
6. Privilege escalation: The attacker uses the compromised certificates to escalate privileges on the target systems.
7. Data access/exfiltration: With elevated privileges, the attacker accesses sensitive data or exfiltrates it from the network.
8. Persistence: The attacker establishes persistence by maintaining access through the compromised certificates.

## Impact

Successful exploitation could allow attackers to gain unauthorized access to critical systems and sensitive data. The compromise of authentication mechanisms can lead to widespread lateral movement within the network, data breaches, and potential disruption of services. The severity depends on the value of the accessed data and the criticality of the compromised systems.

## Recommendation

*   Ensure that the Windows Certificate Services analytic story has 5 or more analytics enabled within Splunk to enable this detection.
*   Investigate any systems flagged by this alert to determine if certificate theft or forgery has occurred, pivoting off of the `risk_object` field.
*   Tune the `steal_or_forge_authentication_certificates_behavior_identified_filter` macro to reduce false positives based on your environment.
*   Review and harden the Windows Certificate Services infrastructure based on the references provided to prevent future attacks targeting certificates.
*   Deploy the provided Splunk search query to detect aggregations of certificate-related risk events.
