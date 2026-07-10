---
title: Cisco ASA AAA Policy Tampering
slug: 2024-01-02-cisco-aaa-tampering
description: Unauthorized modifications to Cisco ASA AAA policies via CLI or ASDM can weaken authentication mechanisms, potentially enabling brute-force attacks, privilege escalation, and persistent access by malicious actors.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cisco-asa
  - aaa-policy
  - privilege-escalation
  - persistence
vendors:
  - Cisco
products:
  - Cisco Adaptive Security Appliance
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Impair Defenses
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/cisco_asa___aaa_policy_tampering.yml
  - https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html
rules:
  - title: Cisco ASA - Suspicious AAA Authentication Policy Modification
    description: Detects modifications to AAA authentication policies on Cisco ASA devices.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1556.004
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA - Suspicious AAA Authorization Policy Modification
    description: Detects modifications to AAA authorization policies on Cisco ASA devices, potentially indicating privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1556.004
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This brief addresses the threat of unauthorized modifications to Authentication, Authorization, and Accounting (AAA) policies on Cisco Adaptive Security Appliance (ASA) devices. Attackers, including malicious insiders, may leverage CLI or ASDM to tamper with AAA settings. The modifications can weaken authentication mechanisms, disable account lockout policies, or elevate privileges. The goal is to facilitate brute-force attacks, maintain persistent access, and potentially compromise the entire network. This activity is typically observed through Cisco ASA syslog data, specifically monitoring command execution events related to AAA policy changes. This attack matters to defenders because a compromised ASA can grant an attacker complete control over the network perimeter.

## Attack Chain

1.  Initial Access: An attacker gains initial access to the Cisco ASA's CLI or ASDM, potentially through compromised credentials or exploiting a vulnerability.
2.  Authentication Policy Modification: The attacker modifies AAA authentication policies using commands like `aaa authentication`, potentially increasing the maximum failed login attempts or disabling account lockout.
3.  Authorization Policy Modification: The attacker modifies AAA authorization policies with commands like `aaa authorization`, escalating privileges for specific user accounts or groups to gain administrative access.
4.  Local Authentication Tampering: The attacker modifies the local authentication database on the ASA with commands like `aaa local authentication`, creating new privileged accounts or modifying existing ones.
5.  AAA Server Configuration Changes: The attacker alters AAA server configurations using commands like `aaa-server`, redirecting authentication requests to a malicious AAA server controlled by the attacker.
6.  Disabling AAA: The attacker disables AAA features entirely using `no aaa` commands, bypassing all authentication and authorization controls.
7.  Persistence: The attacker establishes persistent access by creating or modifying user accounts with elevated privileges, or by maintaining unauthorized access via weakened authentication policies.
8.  Lateral Movement & Data Exfiltration: With elevated privileges, the attacker moves laterally within the network, accessing sensitive data and exfiltrating it to an external location.

## Impact

Compromised AAA policies can lead to significant security breaches. An attacker can gain unauthorized access to sensitive network resources, exfiltrate confidential data, and disrupt critical business operations. Success could allow a malicious actor to pivot within the network, potentially impacting thousands of systems and resulting in substantial financial losses. This attack can severely damage an organization's reputation and erode customer trust.

## Recommendation

*   Enable Cisco ASA syslog data ingestion into your SIEM via the Cisco Security Cloud TA, ensuring message IDs 111008 and 111010 are included in the logs.
*   Deploy the provided Sigma rules to your SIEM to detect suspicious AAA policy modifications.
*   Review and harden AAA policies on Cisco ASA devices regularly, enforcing strong password policies, account lockout thresholds, and multi-factor authentication where possible (reference: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html).
*   Investigate any unauthorized modifications to AAA policies, focusing on changes that weaken security posture, and compare these changes against approved change management processes (see description field).
