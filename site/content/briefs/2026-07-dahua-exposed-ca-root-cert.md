---
title: Dahua IPC Vulnerability CVE-2026-29114 Exposes CA Root Certificate
slug: 2026-07-dahua-exposed-ca-root-cert
description: A low-severity certificate-trust vulnerability (CVE-2026-29114) has been identified in select Dahua IPC (IP camera) models with firmware builds before April 15, 2026. A remote attacker can obtain the device's internal CA root certificate, which, if trusted by client workstations, browsers, or middleware, allows the attacker to mint fraudulent X.509 certificates, enabling person-in-the-middle (MITM) attacks against HTTPS or TLS-protected sessions, undermining confidentiality and integrity, with related CVEs for different impacts. Remediation involves upgrading firmware and removing improperly trusted device CAs from client trust stores.
date: "2026-07-11T07:06:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - certificate-abuse
  - dahua
  - pki
  - mitm
vendors:
  - Dahua Technology
products:
  - Dahua IPC models (firmware before 2026-04-15)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: a remote attacker can obtain the device's internal CA root certificate
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: an attacker who possesses the private key material can mint fraudulent X.509 certificates that validating clients will accept as legitimate.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1557
    technique_name: Man-in-the-Middle
    evidence: enables person-in-the-middle (MITM) attacks against HTTPS or TLS-protected sessions
    confidence_band: high
cves:
  - id: CVE-2026-29114
    epss: 0.0019
  - id: CVE-2026-29115
    epss: 0.00362
  - id: CVE-2026-29116
    epss: 0.00395
references:
  - https://sploitus.com/exploit?id=E9720D7A-AA59-5444-9627-AEFF0E031CDA&utm_source=rss&utm_medium=rss
  - https://www.dahuasecurity.com/about-dahua/trust-center/dahua-psi
rules:
  - title: Detect Suspicious Dahua CA Roots in Windows Trust Store
    description: Detects PowerShell commands auditing the local machine's root certificate store for certificates with 'Dahua', 'OEM', or 'IPC' in their subject, which could indicate the presence of improperly trusted device CAs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1082
      - T1553.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Dahua CA Roots in Linux Trust Store
    description: Detects `grep` commands searching for 'dahua' or 'BEGIN CERTIFICATE' within common Linux certificate authority directories, which could indicate auditing for improperly trusted device CAs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1083
      - T1553.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A low-severity certificate-trust vulnerability, CVE-2026-29114, impacts specific Dahua IPC (IP camera) models running firmware built prior to April 15, 2026. This vulnerability allows a remote attacker to obtain the device's internal CA root certificate. If this exposed root CA (or an intermediate certificate derived from it) has been installed and trusted on client workstations, browsers, or middleware, an attacker possessing the corresponding private key material can forge X.509 certificates that appear legitimate to the trusting clients. This capability enables person-in-the-middle (MITM) attacks against HTTPS or TLS-protected sessions that rely on the compromised trust anchor, severely undermining the confidentiality and integrity of communications. The issue is described with a CVSS 4.0 base score of 2.3 (LOW), largely due to deployment preconditions and passive user interaction requirements. Other related Dahua vulnerabilities, CVE-2026-29115 and CVE-2026-29116, were disclosed concurrently, but affect different products and have distinct impacts, primarily availability.

## Attack Chain

1. An attacker identifies a vulnerable Dahua IPC device with firmware built before April 15, 2026.
2. The attacker remotely accesses the IPC and exploits an unspecified mechanism to obtain the device's internal CA root certificate and potentially its private key material.
3. The attacker utilizes the compromised CA root certificate and private key to mint fraudulent X.509 certificates for arbitrary domains or services.
4. The attacker establishes a Person-in-the-Middle (MITM) position to intercept network traffic between a client and a legitimate service.
5. During the MITM attack, the attacker presents the fraudulently issued X.509 certificate to the client.
6. If the client workstation, browser, or middleware has previously had the compromised Dahua device CA installed and trusted in its trust store, it accepts the fraudulent certificate as legitimate.
7. The attacker then decrypts, inspects, and potentially modifies the TLS-protected traffic between the client and the legitimate service.
8. Confidentiality and integrity of the intercepted communication are compromised, enabling data exfiltration or manipulation.

## Impact

The primary impact of CVE-2026-29114 is the compromise of confidentiality and integrity of TLS-protected communications between client systems and legitimate services, facilitated by person-in-the-middle (MITM) attacks. While the direct impact on the vulnerable Dahua IPC itself is considered low (CVSS 2.3), the real danger lies in the ability of an attacker to forge trusted X.509 certificates. This can lead to sensitive data interception or alteration if client machines (such as operator PCs, VMS middleware, or corporate browsers) have erroneously installed and trust the exposed device CA. The vulnerability does not directly impact the availability of the device, nor does it lead to bulk exfiltration of recorded video. The number of potentially affected organizations and victims is proportional to the deployment of vulnerable Dahua IPC models with unpatched firmware and the practice of installing device CAs into enterprise trust stores.

## Recommendation

* Upgrade all Dahua IPC units with firmware builds before April 15, 2026, to vendor-fixed versions as advised in the Dahua Product Security Incident (PSI) Trust Center reference.
* Remove any Dahua-issued or device-embedded CA root certificates from all client workstation, browser, and middleware trust stores identified by the `Detect Suspicious Dahua CA Roots in Windows Trust Store` and `Detect Suspicious Dahua CA Roots in Linux Trust Store` Sigma rules.
* Deploy the `Detect Suspicious Dahua CA Roots in Windows Trust Store` Sigma rule to monitor PowerShell command line activity for auditing of suspicious root certificates.
* Deploy the `Detect Suspicious Dahua CA Roots in Linux Trust Store` Sigma rule to monitor process creation for `grep` commands searching for suspicious root certificates in common CA directories.
* Implement strict PKI best practices for IPC deployments, ensuring that device-embedded CAs are never trusted enterprise-wide and that public or corporate PKI is preferred.
* Block unauthenticated administrative URLs on Dahua IPCs from untrusted networks to limit initial access opportunities.
