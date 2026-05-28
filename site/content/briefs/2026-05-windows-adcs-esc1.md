---
title: Windows AD CS ESC1 Certificate Authentication Abuse
slug: 2026-05-windows-adcs-esc1
description: This analytic detects the issuance of a suspicious certificate with a Subject Alternative Name (SAN) using Active Directory Certificate Services (AD CS) and its immediate use for authentication, indicating potential exploitation of improperly configured certificate templates for privilege escalation.
date: "2026-05-28T18:00:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - adcs
  - certificate_abuse
  - privilege_escalation
  - windows
vendors:
  - Microsoft
products:
  - Active Directory Certificate Services
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1649
    technique_name: OS Configuration Abuse
references:
  - https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
  - https://github.com/ly4k/Certipy#esc1
  - https://pentestlaboratories.com/2021/11/08/threat-hunting-certificate-account-persistence/
rules:
  - title: Detect AD CS ESC1 Certificate Authentication Abuse
    description: Detects AD CS ESC1 certificate authentication abuse by monitoring for certificate issuance (Event ID 4887) followed by Kerberos authentication (Event ID 4768).
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550
      - T1649
    data_sources:
      - windows
      - windows
  - title: Detect Kerberos Authentication with Newly Issued Certificate
    description: Detects Kerberos authentication events using a certificate shortly after a certificate issuance event is logged, indicating potential abuse.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1550
      - T1649
    data_sources:
      - windows
      - windows
rules_count: 2
---

This detection identifies potential abuse of Active Directory Certificate Services (AD CS) through ESC1 (Enterprise Subordinate Certification Authority 1) authentication. The technique involves exploiting misconfigured certificate templates to issue certificates with Subject Alternative Names (SANs), which are then used for authentication. This can lead to privilege escalation and complete environment compromise. The detection focuses on Windows Security Event Logs, specifically Event ID 4887 for certificate issuance and Event ID 4768 for Kerberos authentication using the issued certificate. It is critical for defenders because successful exploitation allows attackers to impersonate legitimate users and services, gaining unauthorized access and potentially escalating privileges to domain administrator. The activity is often associated with tools like Certipy.

## Attack Chain

1. An attacker identifies an AD CS server with improperly configured certificate templates that allow for SAN spoofing (e.g., ESC1 template).
2. The attacker uses tools like Certipy or Certify to request a certificate based on a vulnerable template. The request includes a Subject Alternative Name (SAN) that matches a target user's User Principal Name (UPN).
3. The AD CS server issues a certificate with the specified SAN, allowing it to be used for authentication. Windows Security Event 4887 is logged.
4. The attacker imports the issued certificate into their user context on the attacking machine.
5. The attacker uses the certificate to request a Kerberos Ticket Granting Ticket (TGT) for the target user. Windows Security Event 4768 is logged.
6. The Kerberos TGT is successfully obtained, enabling the attacker to authenticate as the target user.
7. The attacker leverages the impersonated user's privileges to access sensitive resources, escalate privileges, or move laterally within the network.

## Impact

Successful exploitation of AD CS via ESC1 authentication abuse can lead to complete domain compromise. Attackers can gain unauthorized access to sensitive data, escalate privileges to domain administrator, and move laterally across the network. This can result in data breaches, system downtime, and significant financial losses. The impact is especially severe in environments with critical infrastructure or sensitive data.

## Recommendation

*   Enable enhanced Audit Logging on AD CS and within Group Policy Management for CS servers (reference: SpecterOps Certified Pre-Owned whitepaper).
*   Deploy the Sigma rule "Detect AD CS ESC1 Certificate Authentication Abuse" to your SIEM and tune for your environment to detect Event ID 4887 and 4768 activity indicative of certificate abuse.
*   Review and harden certificate templates to prevent SAN spoofing (reference: SpecterOps Certified Pre-Owned whitepaper).
*   Monitor Event ID 4768 for Kerberos authentication events with certificates, and correlate them with recent certificate issuance events (Event ID 4887).
*   Implement the provided Sigma rule "Detect Kerberos Authentication with Newly Issued Certificate" to identify authentication events shortly after certificate issuance, to detect related Event ID 4768 activity.
*   Investigate any instances of Event ID 4887 where certificates are issued with Subject Alternative Names (SANs) containing UPNs.
