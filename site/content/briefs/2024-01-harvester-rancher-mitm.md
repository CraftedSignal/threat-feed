---
title: SUSE Harvester Rancher Integration Vulnerable to MITM and DOS
slug: 2024-01-harvester-rancher-mitm
description: SUSE Harvester's Rancher integration mechanism is vulnerable to a man-in-the-middle attack due to insecure TLS options, potentially leading to denial of service.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - mitm
  - denial-of-service
  - virtualization
vendors:
  - SUSE
products:
  - Harvester
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-pgh9-mpwc-8jjf
  - https://attack.mitre.org/techniques/T1557/
  - https://attack.mitre.org/techniques/T1499/004/
rules:
  - title: Detect Connection to Unvalidated Certificate Authority
    description: Detects connections where certificate validation is disabled, which could indicate a MITM attack.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1557
    data_sources:
      - network_connection
      - linux
  - title: Detect Abnormal Process Crash
    description: Detects unexpected process crashes which can be a sign of a buffer overflow.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect modification of cluster registration URL
    description: Detects unauthorized modifications to the cluster registration URL, which is a critical setting for Rancher integration.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

SUSE Harvester, a hyperconverged infrastructure (HCI) solution, integrates with Rancher to manage Kubernetes clusters. A vulnerability exists in the cluster registration process. The registration client, responsible for establishing communication between Harvester and Rancher, uses an insecure TLS configuration by default, failing to validate the remote server's certificate. This vulnerability, discovered in versions prior to 1.8.0, allows an attacker with network-level access to intercept and manipulate the TLS handshake, potentially redirecting cluster registration requests to a malicious server. Successful exploitation can result in unauthorized access and control over the Harvester cluster or lead to a denial of service condition due to a memory buffer overflow when processing unvalidated response payloads.

## Attack Chain

1.  Attacker gains network-level access between the SUSE Virtualization instance and the Rancher Manager.
2.  The Harvester registration client attempts to establish a TLS connection with the Rancher Manager using the insecure default configuration.
3.  Attacker intercepts the TLS handshake.
4.  Attacker presents a fraudulent certificate to the Harvester registration client. Due to the lack of certificate validation, the client accepts the certificate.
5.  The Harvester registration client sends cluster registration requests to the attacker-controlled server.
6.  Attacker's server sends a crafted response payload back to the Harvester registration client.
7.  The Harvester registration client processes the response payload without proper size validation.
8.  A memory buffer overflow occurs, leading to a crash of the SUSE Virtualization registration controller, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability allows an attacker to perform a man-in-the-middle attack and potentially gain unauthorized access to the SUSE Harvester cluster. Furthermore, the vulnerability can be exploited to cause a denial-of-service condition by crashing the SUSE Virtualization registration controller. While the exact number of affected installations is unknown, organizations using SUSE Harvester versions prior to 1.8.0 are at risk. Sectors commonly using virtualization technologies, such as cloud service providers, financial institutions, and research organizations, are potentially affected.

## Recommendation

*   Upgrade SUSE Virtualization to version 1.8.0 or later to patch the vulnerability as recommended by the vendor.
*   As a workaround, restrict access to the `cluster-registration-url` setting to authorized cluster administrators.
