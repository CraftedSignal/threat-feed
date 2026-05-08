---
title: free5GC NEF Unauthenticated PFD Management API
slug: 2026-05-free5gc-nef-auth-bypass
description: free5GC's NEF component has an unauthenticated API endpoint allowing attackers to create, read, and delete PFD management transactions by bypassing authentication, leading to policy poisoning, data leaks, and denial of service; this affects versions up to v4.2.1.
date: "2026-05-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - free5GC
  - authentication-bypass
  - pfd-management
  - network
vendors:
  - free5GC
products:
  - nef (<=v4.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Credential Access
references:
  - https://github.com/advisories/GHSA-5f62-53r8-qrqf
  - https://github.com/free5gc/free5gc/issues/858
  - https://github.com/free5gc/nef/pull/23
iocs:
  - type: url
    value: http://10.100.200.19:8000/3gpp-traffic-influence/v1/af-poc-pfd2/subscriptions
  - type: url
    value: http://10.100.200.19:8000/3gpp-pfd-management/v1/af-poc-pfd2/transactions
ioc_counts:
  url: 2
rules:
  - title: Detect free5GC NEF Unauthenticated PFD Transaction Creation
    description: Detects CVE-2026-44315 exploitation — Creation of PFD transactions in free5GC NEF without proper authentication by monitoring POST requests to the /transactions endpoint with suspicious authorization headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect free5GC NEF Unauthenticated PFD Management Access
    description: Detects CVE-2026-44315 exploitation — Attempts to access PFD management API endpoints in free5GC NEF without proper authentication by monitoring GET and DELETE requests to /transactions/{transID} endpoint with suspicious authorization headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The free5GC NEF (Network Exposure Function) component, in versions up to v4.2.1, exposes a critical security vulnerability in its `3gpp-pfd-management` API. This API lacks proper inbound authentication and authorization controls. A network attacker who can reach the NEF on the SBI (Service Based Interface) can exploit this flaw to create, read, and delete PFD (PFD-management) transaction states using arbitrary bearer tokens. The route group remains accessible even when operators attempt to disable it via configuration settings. This issue was validated against the NEF container in the official Docker compose lab, specifically version v4.2.0 with runtime commit `5ce35eab`.  The vulnerability allows attackers to manipulate policy and traffic routing within the 5G network.

## Attack Chain

1.  Attacker gains network access to the SBI of the free5GC NEF.
2.  Attacker crafts a malicious HTTP POST request to `/3gpp-traffic-influence/v1/af-poc-pfd2/subscriptions` with a forged bearer token to seed an AF context.
3.  Attacker crafts a malicious HTTP POST request to `/3gpp-pfd-management/v1/af-poc-pfd2/transactions` with a forged bearer token, containing attacker-controlled PFD data, to create a new PFD transaction.
4.  The NEF, lacking authentication, accepts the forged token and creates the PFD transaction, writing the data to the UDR (User Data Repository).
5.  Attacker crafts a malicious HTTP GET request to `/3gpp-pfd-management/v1/af-poc-pfd2/transactions/{transID}` with a forged bearer token to read the created transaction.
6.  Attacker crafts a malicious HTTP DELETE request to `/3gpp-pfd-management/v1/af-poc-pfd2/transactions/{transID}` with a forged bearer token to delete the PFD transaction.
7.  The NEF, lacking authorization, processes the DELETE request, removing the PFD transaction state from the UDR.
8.  Downstream components (SMF/UPF) now use poisoned policy state based on the forged PFD transactions, leading to traffic misclassification or denial of service.

## Impact

The unauthenticated `3gpp-pfd-management` API allows attackers to manipulate PFD transactions within the free5GC NEF, potentially affecting all subscribers. By creating attacker-controlled PFD transactions, they can poison policy state used by SMF/UPF for traffic classification. Attackers can also read existing PFD transactions to leak AF-supplied policy data or delete PFD transactions to cause denial of service. The fact that the API is reachable even when disabled via configuration increases the attack surface and the risk. Successful exploitation could lead to widespread service disruption, data breaches, and financial losses.

## Recommendation

*   Apply the official patch available in the upstream fix [https://github.com/free5gc/nef/pull/23](https://github.com/free5gc/nef/pull/23) to remediate the vulnerability.
*   Deploy the Sigma rule "Detect free5GC NEF Unauthenticated PFD Transaction Creation" to identify attempts to create PFD transactions with forged tokens.
*   Deploy the Sigma rule "Detect free5GC NEF Unauthenticated PFD Management Access" to detect unauthorized access attempts to the PFD management API.
*   Monitor network traffic to the NEF on the SBI for suspicious activity and forged authorization headers, specifically using the IOCs provided in this brief.
*   Ensure that the NEF is properly configured with appropriate firewall rules to restrict access to authorized entities only.
