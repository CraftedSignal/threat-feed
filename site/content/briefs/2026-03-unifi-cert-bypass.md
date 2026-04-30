---
title: UniFi Network Controller Improper Certificate Verification Vulnerability (CVE-2019-25652)
slug: 2026-03-unifi-cert-bypass
description: UniFi Network Controller versions before 5.10.22 and 5.11.x before 5.11.18 contain an improper certificate verification vulnerability, enabling adjacent network attackers to perform man-in-the-middle attacks by presenting a fraudulent SSL certificate during SMTP connections to intercept traffic and steal credentials.
date: "2026-03-27T22:16:19Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - unifi
  - mitm
  - credential-theft
  - cve-2019-25652
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Man-in-the-Middle
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25652
  - https://community.ui.com/releases/Security-Advisory-Bulletin-003-003/982bbaa8-2a07-4f81-a5f6-0bb84753f391
  - https://www.vulncheck.com/advisories/unifi-network-controller-improper-certificate-validation-leading-to-credential-theft-via-mitm
rules:
  - title: Detect Self-Signed Certificates in SMTP Traffic
    description: Detects the use of self-signed certificates during SMTP communication, which could indicate a man-in-the-middle attack exploiting CVE-2019-25652.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1557.001
      - T1588.002
    data_sources:
      - network_connection
      - firewall
  - title: Detect Unifi SMTP Traffic to External IP
    description: Detects Unifi device connecting to external SMTP server.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

CVE-2019-25652 affects UniFi Network Controller versions prior to 5.10.22 and 5.11.x before 5.11.18. The vulnerability stems from an improper certificate verification process during SMTP connections. An attacker positioned on an adjacent network can exploit this weakness to conduct man-in-the-middle (MitM) attacks. By presenting a false SSL certificate, the attacker can intercept SMTP traffic intended for the UniFi Network Controller, potentially gaining access to sensitive information…
