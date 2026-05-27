---
title: Samba Certificate Auto-Enrollment Vulnerability (CVE-2026-3012)
slug: 2026-05-samba-cert-enrollment-vuln
description: CVE-2026-3012 describes a vulnerability in Samba's certificate auto-enrollment Group Policy handling, where retrieval of CA certificates over unencrypted HTTP connections without proper verification could allow attackers to supply malicious certificates, leading to interception or spoofing of trusted communications.
date: "2026-05-27T11:17:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - samba
  - certificate-enrollment
  - man-in-the-middle
  - cve-2026-3012
vendors:
  - Samba
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
cves:
  - id: CVE-2026-3012
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3012
rules:
  - title: Detect CVE-2026-3012 Exploitation — Unencrypted HTTP for CA Certificate Retrieval
    description: Detects CVE-2026-3012 — Monitors network connections for unencrypted HTTP traffic originating from Samba server, specifically targeting CA certificate retrieval.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Untrusted Certificate Added to Trust Store
    description: Detects the addition of an untrusted certificate to the system's trust store using certutil.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability, identified as CVE-2026-3012, resides within the certificate auto-enrollment Group Policy handling of Samba. When certificate auto-enrollment is active, Samba might retrieve Certificate Authority (CA) certificates via an unencrypted HTTP connection. Crucially, it installs these certificates into the local trust store without conducting adequate verification. This poses a significant security risk because an attacker who can intercept or redirect network traffic can exploit this behavior. The attacker could supply a malicious CA certificate, potentially enabling them to intercept trusted communications or spoof legitimate entities. This vulnerability is particularly relevant for organizations using Samba for file and print services in a Windows Active Directory environment.

## Attack Chain

1. An administrator enables certificate auto-enrollment in Samba through Group Policy.
2. Samba attempts to retrieve a Certificate Authority (CA) certificate.
3. Due to the vulnerability, Samba uses an unencrypted HTTP connection to fetch the CA certificate.
4. An attacker intercepts the HTTP request for the CA certificate.
5. The attacker injects a malicious CA certificate into the HTTP response.
6. Samba installs the attacker's malicious CA certificate into the local trust store, without proper validation.
7. Clients connecting to Samba may now trust services or servers signed by the malicious CA.
8. The attacker can intercept or spoof communications intended for legitimate servers, such as SMB traffic or web server connections, by presenting certificates signed by the malicious CA.

## Impact

Successful exploitation of this vulnerability (CVE-2026-3012) could allow an attacker to perform man-in-the-middle attacks, intercept sensitive data transmitted between clients and the Samba server, and spoof trusted communications. This could lead to the compromise of user credentials, data breaches, and the disruption of critical services. Given the widespread use of Samba in enterprise environments, the potential number of affected organizations is substantial.

## Recommendation

*   Implement network monitoring to detect unencrypted HTTP traffic used for retrieving CA certificates originating from the Samba server (see network_connection log source).
*   Deploy the Sigma rule to detect the addition of untrusted certificates to the system's trust store (see file_event log source).
*   Ensure that Samba is configured to use HTTPS for certificate retrieval where possible, mitigating the risk of interception.
