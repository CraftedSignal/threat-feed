---
title: epa4all-client Library Vulnerable to TLS Certificate Validation Issue (CVE-2026-45574)
slug: 2026-05-epa4all-client-tls-validation
description: The epa4all-client library before version 1.2.2 is vulnerable to a TLS certificate validation issue, allowing a man-in-the-middle attacker to intercept SOAP traffic and sensitive patient data by presenting a malicious TLS certificate.
date: "2026-05-15T18:29:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - tls
  - certificate-validation
  - mitm
  - credential-access
  - cve-2026-45574
vendors:
  - Oviva AG
products:
  - epa4all-client (< 1.2.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-5hhf-xmfx-4vvr
  - https://github.com/oviva-ag/epa4all-client/pull/36
iocs:
  - type: email
    value: contact@machinespirits.de
ioc_counts:
  email: 1
rules:
  - title: Detect epa4all-client with Disabled TLS Validation - Outbound Connection
    description: Detects outbound network connections from processes associated with the vulnerable epa4all-client library that may be indicative of exploitation of CVE-2026-45574 where TLS validation is disabled.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1071.001
      - T1588.004
    data_sources:
      - network_connection
      - windows
  - title: Detect epa4all-client with Disabled TLS Validation - Process Creation
    description: Detects process creation events indicative of the vulnerable epa4all-client library being executed which may lead to CVE-2026-45574 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - execution
    techniques:
      - T1588.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `epa4all-client` library, used for electronic patient record (ePA) interactions, contains a flaw that disables TLS certificate validation in production environments. This vulnerability, present in versions prior to 1.2.2, allows an attacker positioned on the network path between the ePA service and the Konnektor to intercept all SOAP traffic. This includes sensitive information such as patient identifiers (KVNR), SMC-B card operations (authentication, signing), document content, and credential exchanges. The vulnerability is identified as CVE-2026-45574 and was reported by Machine Spirits. Exploitation of this flaw allows for significant data breaches and unauthorized access to patient information.

## Attack Chain

1. An attacker positions themselves on the network path between the ePA client (using the vulnerable library) and the ePA service/Konnektor.
2. The ePA client attempts to establish a TLS connection to the ePA service.
3. The attacker intercepts the TLS handshake and presents a malicious TLS certificate (self-signed, expired, or with a wrong CN).
4. Due to the disabled TLS certificate validation in the vulnerable `epa4all-client` library, the client accepts the malicious certificate without proper verification.
5. A secure TLS connection is established between the ePA client and the attacker, who is impersonating the legitimate ePA service.
6. The ePA client sends SOAP requests containing sensitive data (patient identifiers, SMC-B card operations, document content, and credentials) over the TLS connection.
7. The attacker intercepts and decrypts the SOAP traffic, gaining access to the sensitive data.
8. The attacker can then use the stolen data for malicious purposes, such as identity theft, fraud, or unauthorized access to patient records.

## Impact

Successful exploitation of this vulnerability allows an attacker to intercept and steal sensitive patient data transmitted between the ePA client and the ePA service. This includes patient identifiers (KVNR), SMC-B card operations (authentication, signing), document content, and credential exchanges. A successful attack could lead to large-scale data breaches, identity theft, and unauthorized access to confidential patient records, impacting potentially thousands of patients and healthcare providers using the vulnerable `epa4all-client` library.

## Recommendation

*   Upgrade the `epa4all-client` library to version 1.2.2 or later to remediate the TLS certificate validation vulnerability (CVE-2026-45574).
*   As a workaround, use the library directly instead of the REST wrapper as suggested in the advisory.
*   Monitor network traffic for unexpected TLS connections originating from applications using the `epa4all-client` library, using the rules below, especially if connections use non-standard certificates.
