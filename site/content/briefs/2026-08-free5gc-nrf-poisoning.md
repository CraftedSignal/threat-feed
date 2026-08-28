---
title: free5GC NRF NF Registration Poisoning via Input Validation Failure
slug: 2026-08-free5gc-nrf-poisoning
description: The free5GC Network Repository Function (NRF) fails to validate NF registration requests against 3GPP TS 29.510 standards, allowing unauthenticated attackers to inject fraudulent network function profiles into the 5G core service mesh.
date: "2026-08-28T21:13:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:free5gc:free5gc:*:*:*:*:*:*:*:*
tags:
  - 5g-core
  - free5gc
  - nrf
  - cve-2026-55068
  - input-validation
vendors:
  - free5GC
products:
  - free5GC (< 4.2.2)
affected_os:
  - Ubuntu 22.04
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The free5GC NRF lacks NF Profile input validation, allowing unauthenticated attackers to inject fake NF profiles.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: An attacker with SBI network access can intercept control-plane signaling, harvest OAuth2 credentials, and deny service to subscribers.
    confidence_band: high
cves:
  - id: CVE-2026-55068
references:
  - https://github.com/advisories/GHSA-x8mj-6p3q-g5pp
rules:
  - title: Detect Anomalous NF Registration Requests
    description: Detects potential NF registration poisoning by identifying PUT requests to the NRF registration endpoint that include suspicious or malformed fields typical of the documented CVE-2026-55068 exploit.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade free5GC to version 4.2.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states versions < 4.2.2 are vulnerable.
  hunt_leads:
    - lead: Audit NRF registration logs for non-UUID identifiers.
      technique_id: T1190
      data_needed:
        - Web server logs for NRF endpoint
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source shows non-UUID strings are accepted for registration.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.2.2
      owner: IT Operations
      addresses: CVE-2026-55068
      evidence: Source-provided fix.
---

The free5GC Network Repository Function (NRF) exhibits a critical security vulnerability (CVE-2026-55068) in the `RegisterNFInstance` handler, which processes PUT requests at `/nnrf-nfm/v1/nf-instances/{nfInstanceID}`. The NRF accepts NF registration requests without performing input validation against mandatory 3GPP TS 29.510 constraints, including UUID formats, enum values, numeric ranges, and field requirements. 

This lack of validation permits unauthenticated attackers to register arbitrary NF profiles, including those with attacker-controlled IP addresses and ports within the `ipEndPoints` parameter. Once registered, these malicious profiles are stored in the backend MongoDB and distributed to other network functions via the `NFDiscover` service. This leads to service mesh poisoning, where legitimate network functions like the SMF, AMF, or PCF are tricked into routing control-plane signaling to attacker-controlled endpoints. This vulnerability enables man-in-the-middle interception of sensitive 5G control-plane traffic, OAuth2 credential harvesting, and widespread denial-of-service conditions across the 5G core infrastructure.

## Attack Chain

1. An attacker gains access to the Service-Based Architecture (SBI) network.
2. The attacker crafts a malicious JSON payload mimicking an NF registration request that violates multiple 3GPP constraints.
3. The attacker sends a PUT request to the NRF endpoint `/nnrf-nfm/v1/nf-instances/` containing the forged `nfInstanceId`.
4. The NRF server accepts the invalid request and returns HTTP 201 without validating field integrity.
5. The NRF stores the fraudulent NF profile in its backend MongoDB collection.
6. A legitimate network function (e.g., SMF) queries the NRF for available NF instances using the `NFDiscover` API.
7. The NRF returns the malicious profile to the requester in the discovery response.
8. The legitimate NF selects the attacker-controlled endpoint and attempts to route control-plane signaling to the attacker's server.

## Impact

Successful exploitation allows attackers to compromise the integrity of the entire 5G core service mesh. By redirecting control-plane signaling, an attacker can intercept subscriber traffic, harvest OAuth2 security credentials used for inter-service authentication, and cause systemic denial-of-service for connected subscribers. This vulnerability affects all components of the free5GC suite that rely on the NRF for service discovery, including AMF, SMF, AUSF, UDM, PCF, and NSSF. All versions of free5GC prior to 4.2.2 are vulnerable.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade all instances of free5GC to version 4.2.2 or later immediately to apply the patch for CVE-2026-55068.
- Implement a JSON schema validator for the MongoDB `NfProfile` collection to prevent the storage of malformed NF instances.
- Enable NRF auditing and logging; although logging does not prevent the attack, it provides the necessary telemetry to detect anomalous NF registration attempts.
- Implement strict ingress filtering and mTLS for the SBI interface to ensure that only authorized Network Functions can interact with the NRF registration endpoint.
- Deploy the provided Sigma rule to detect anomalous HTTP PUT registration requests at the NRF interface.
