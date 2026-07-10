---
title: Suspicious Certificate Issuance and Authentication via AD CS ESC1
slug: 2024-01-03-esc1-certificate-abuse
description: This analytic detects suspicious certificate issuance with a Subject Alternative Name (SAN) via Active Directory Certificate Services (AD CS) followed by immediate authentication, using Windows Security Event Logs (EventCode 4887 and 4768), which, if successful, can lead to privilege escalation and environment compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esc1
  - certificate_abuse
  - privilege_escalation
  - windows
vendors:
  - Microsoft
products:
  - Active Directory Certificate Services
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1649
    technique_name: System Firmware
references:
  - https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
  - https://github.com/ly4k/Certipy#esc1
  - https://pentestlaboratories.com/2021/11/08/threat-hunting-certificate-account-persistence/
rules:
  - title: Detect Suspicious Certificate Issuance with SAN
    description: Detects certificate issuance events (Event ID 4887) where the certificate contains a Subject Alternative Name (SAN) with a User Principal Name (UPN), indicative of potential ESC1 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1550
    data_sources:
      - process_creation
      - windows
  - title: Detect Kerberos Authentication with Newly Issued Certificate
    description: Detects Kerberos authentication events (Event ID 4768) where the certificate thumbprint is present, suggesting authentication using a certificate. This rule looks for Event ID 4768 occuring shortly after 4887
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1550
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential abuse of Active Directory Certificate Services (AD CS) through the ESC1 attack vector. This involves the issuance of a suspicious certificate containing a Subject Alternative Name (SAN) followed by its immediate use for authentication. The activity is detected by correlating Windows Security Event Logs, specifically Event ID 4887 (certificate issuance) and Event ID 4768 (Kerberos authentication). This technique exploits improperly configured certificate templates within AD CS, which can lead to unauthorized privilege escalation and full compromise of the Windows environment. The activity is significant as a successful attacker can gain domain administrator privileges using tools like Certipy, potentially leading to lateral movement, data exfiltration, or deployment of ransomware. The detection leverages the Splunk ES datamodel and is based on work published by SpecterOps and others.

## Attack Chain

1.  The attacker compromises a user account or gains access to a system with permissions to request certificates.
2.  The attacker identifies vulnerable certificate templates that allow for Subject Alternative Name (SAN) spoofing, specifically user principal name (UPN).
3.  The attacker crafts a certificate request, forging the SAN to impersonate a high-privilege user (e.g., Domain Admin).
4.  The attacker submits the malicious certificate request to the AD CS server, triggering Event ID 4887, which indicates a certificate with a SAN was issued.
5.  The AD CS server, if misconfigured, issues the certificate based on the tampered request.
6.  The attacker uses the issued certificate to request a Kerberos Ticket Granting Ticket (TGT) for the impersonated user, generating Windows Event ID 4768 with the certificate thumbprint.
7.  The attacker successfully authenticates as the high-privilege user.
8.  The attacker uses the elevated privileges to perform malicious activities, such as lateral movement, data exfiltration, or domain compromise.

## Impact

A successful attack can lead to complete domain compromise. By exploiting misconfigured certificate templates, attackers can escalate privileges to domain administrator, gaining full control over the Active Directory environment. This allows them to move laterally within the network, access sensitive data, deploy ransomware, or disrupt critical services. The impact can be widespread, affecting all systems and users within the compromised domain, causing significant financial and reputational damage.

## Recommendation

*   Enable enhanced audit logging on AD CS and within Group Policy Management for CS server as outlined in the Certified Pre-Owned whitepaper (reference URL).
*   Deploy the Sigma rule "Detect Suspicious Certificate Issuance with SAN" to detect Event ID 4887 with attributes indicative of ESC1 exploitation.
*   Deploy the Sigma rule "Detect Kerberos Authentication with Newly Issued Certificate" to detect Event ID 4768 that correlates with recent certificate issuance activity.
*   Review and remediate any certificate templates that allow for arbitrary SAN values to prevent ESC1 exploitation as described in the SpecterOps whitepaper.
*   Throttle correlation by RequestId/ssl_serial to reduce false positives and improve detection fidelity, as mentioned in the "how_to_implement" section.
