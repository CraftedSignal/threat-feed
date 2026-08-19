---
title: Hard-Coded JWT Signing Secret in Cudy WR3000 Firmware
slug: 2026-08-cudy-jwt-secret
description: Cudy WR3000 routers running firmware prior to 2.5.24 contain a hard-coded HMAC secret in the Mosquitto MQTT broker plugin, enabling unauthenticated attackers to forge JWT tokens and gain unauthorized mesh interface access.
date: "2026-08-19T16:38:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Cudy
products:
  - WR3000
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Cudy WR3000 2.0 running firmware before 2.5.24 contains a hard-coded JWT HMAC signing secret vulnerability in the Mosquitto MQTT broker's authentication plugin that allows unauthenticated attackers to forge valid JWT tokens by extracting the secret from the firmware image.
    confidence_band: high
cves:
  - id: CVE-2026-71960
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71960
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Cudy WR3000 firmware to version 2.5.24 or later
      owner: IT Operations
      due: 24h
      evidence: Cudy WR3000 2.0 running firmware before 2.5.24 contains a hard-coded JWT HMAC signing secret
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to device management and MQTT interfaces
      owner: IT Operations
      addresses: CVE-2026-71960
      evidence: Vulnerability allows unauthenticated attackers to forge valid JWT tokens
---

Cudy WR3000 2.0 routers running firmware versions prior to 2.5.24 contain a critical security vulnerability involving a hard-coded HMAC signing secret located within the Mosquitto MQTT broker authentication plugin. Because this secret is static across device deployments and embedded directly within the firmware image, an attacker who obtains the firmware can extract the key. With the secret in possession, an attacker can sign arbitrary JSON Web Tokens (JWT). By presenting these forged tokens to the MQTT broker, an attacker can bypass authentication mechanisms entirely. This allows for unauthorized access to the device's mesh networking interface, potentially leading to full control over device routing, interception of traffic, or modification of mesh network configurations. Given the ease of extraction and the severity of the access granted, this vulnerability presents a high risk for local network compromises.

## Attack Chain

1. Attacker downloads the target firmware image for Cudy WR3000 from the vendor website.
2. Attacker uses firmware analysis tools (e.g., binwalk) to extract the file system.
3. Attacker identifies the Mosquitto MQTT broker binary and its associated configuration or plugin files.
4. Attacker performs static analysis (e.g., strings or hex analysis) to locate the hard-coded HMAC secret within the binary.
5. Attacker uses a JWT library to create a forged token payload, signing it with the discovered HMAC secret.
6. Attacker sends a crafted authentication request to the MQTT broker interface on the target router using the forged token.
7. The MQTT broker validates the forged signature against the hard-coded secret and grants an authenticated session.
8. Attacker accesses the mesh networking interface to monitor or reconfigure the device.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass authentication on the target Cudy WR3000 device. By gaining access to the mesh networking interface, an attacker can manipulate network traffic, intercept sensitive data moving across the mesh, or leverage the device as a pivot point for further attacks on the internal network.

## Recommendation

Prioritized actions for security and IT teams:
- Update all Cudy WR3000 devices to firmware version 2.5.24 or later immediately.
- If immediate patching is not possible, segment the management interface of the Cudy WR3000 from untrusted network segments to prevent access by unauthorized users.
- Monitor network traffic destined for the MQTT broker ports on these devices for suspicious authentication activity.
