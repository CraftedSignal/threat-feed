---
title: IDOR Vulnerability in FastBee DeviceController
slug: 2026-10-fastbee-idor
description: An insecure direct object reference vulnerability in FastBee versions through 2.1.0 allows authenticated low-privileged users to access and modify devices belonging to other tenants.
date: "2026-10-13T18:38:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fastbee:fastbee:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - idor
  - cve-2026-110124
vendors:
  - FastBee
products:
  - FastBee (<= 2.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated low-privilege user can exploit this to enumerate device identifiers, allowing them to read sensitive data or modify device associations.
    confidence_band: high
cves:
  - id: CVE-2026-110124
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110124
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FastBee beyond 2.1.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110124 vulnerability description
  hunt_leads:
    - lead: Identify API request patterns with sequential deviceId modification
      technique_id: T1068
      data_needed:
        - Webserver request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source describes enumeration of deviceId or serialNumber values
  mitigation_plan:
    - priority: immediate
      action: Enforce server-side authorization for all device resource requests
      owner: IT Operations
      addresses: CVE-2026-110124
      evidence: Source identifies IDOR vulnerability in DeviceController
---

FastBee versions 2.1.0 and earlier are affected by an insecure direct object reference (IDOR) vulnerability located within the DeviceController component. This vulnerability stems from improper authorization checks when handling requests directed at specific device identifiers. An authenticated user with low privileges can exploit this by manipulating the deviceId or serialNumber parameters in API requests. By supplying sequential or brute-forced identifiers, an attacker can bypass access controls to view sensitive information including device owner details, IP addresses, and physical locations. Furthermore, the vulnerability allows unauthorized modification of device associations, where an attacker can overwrite user_id and tenant_id fields to assume control over devices belonging to other tenants within the platform. Given the high CVSS base score of 8.1, this vulnerability poses a significant risk of data exfiltration and cross-tenant device hijacking in multi-tenant environments.

## Attack Chain

1. Attacker authenticates to the FastBee platform using a legitimate, low-privileged user account.
2. Attacker performs discovery to identify the API endpoints associated with DeviceController.
3. Attacker captures an API request intended to retrieve details for their own device.
4. Attacker modifies the request parameters (e.g., deviceId or serialNumber) to target IDs outside their assigned tenant scope.
5. Attacker iterates through sequential or guessed identifiers to enumerate available devices in the platform.
6. Attacker observes sensitive device metadata, such as IP addresses and owner info, returned in the API responses.
7. Attacker crafts a PUT/POST request with malicious user_id and tenant_id values to associate a target device with their own account.
8. Attacker successfully gains full control over the target device, effectively hijacking the asset from the original owner.

## Impact

The vulnerability allows for unauthorized access to sensitive telemetry data and complete takeover of IoT device management. In a multi-tenant environment, this leads to cross-tenant data leakage and the loss of administrative control over devices, potentially affecting any organization using FastBee deployments. The scope of impact includes unauthorized surveillance of device locations and the potential for persistent control over third-party hardware.

## Recommendation

Prioritized actions for addressing CVE-2026-110124:

* Immediately upgrade all FastBee instances to a version beyond 2.1.0 that includes the vendor-provided patch.
* Audit webserver access logs for anomalous API request patterns, specifically searching for successful responses (HTTP 200) following a series of incrementing or high-frequency deviceId parameter values.
* Implement strict authorization checks at the application controller layer to ensure that the currently authenticated user session has explicit permissions to access or modify the requested resource ID.
* Monitor for unexpected spikes in device reassignment events within the DeviceController service logs.
