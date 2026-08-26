---
title: Critical Unauthenticated RCE in ILIAS via Insecure Deserialization
slug: 2026-08-ilias-deserialization
description: An unauthenticated remote code execution vulnerability (CVE-2026-80428) in ILIAS allows attackers to achieve arbitrary file writes and code execution by exploiting insecure deserialization within the Shibboleth logout-notification handler.
date: "2026-08-26T16:20:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - ILIAS
products:
  - ILIAS (9.x)
  - ILIAS (10.x)
  - ILIAS (11.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Shibboleth back-channel endpoint at components/ILIAS/AuthShibboleth/resources/shib_logout.php runs in a context that ilInitialisation exempts from authentication.
    confidence_band: high
cves:
  - id: CVE-2026-80428
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80428
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch ILIAS to version 9.22, 10.10, or 11.3.
      owner: IT Operations
      due: 24h
      evidence: ILIAS versions 9.22, 10.10 and 11.3 remove the endpoint's logout-notification implementation.
  mitigation_plan:
    - priority: immediate
      action: Restrict web access to /components/ILIAS/AuthShibboleth/resources/shib_logout.php at the firewall or reverse proxy level.
      owner: IT Operations
      addresses: CVE-2026-80428
      evidence: The endpoint is the vector for the unauthenticated deserialization exploit.
---

ILIAS, an open-source learning management system, contains a critical insecure deserialization vulnerability (CVE-2026-80428) affecting versions prior to 9.22, 10.10, and 11.3. The vulnerability resides in the Shibboleth back-channel logout-notification handler located at 'components/ILIAS/AuthShibboleth/resources/shib_logout.php'. This endpoint is improperly exempted from authentication checks. When an unauthenticated caller triggers this handler, the application iterates through all live rows in the session table and processes their stored data using an unrestricted 'unserialize()' call. 

An attacker can populate these session rows by leveraging the LTI authentication entry point, which stores request parameters into the session without requiring prior authentication. By injecting a serialized object into the session, the attacker forces the application to instantiate the object upon the call to 'unserialize()'. Through the use of application-bundled gadget chains that trigger filesystem writes upon object destruction, an attacker can write malicious code to an arbitrary location below the web root, resulting in full remote code execution as the web server user.

## Attack Chain

1. The attacker identifies the LTI authentication endpoint that stores request parameters into session data without authentication.
2. The attacker crafts a malicious serialized object payload designed to trigger a filesystem write during the object's destruction phase.
3. The attacker sends a crafted request to the LTI entry point, placing the malicious serialized object into a session table row.
4. The attacker sends an unauthenticated HTTP request to the Shibboleth logout-notification handler ('/components/ILIAS/AuthShibboleth/resources/shib_logout.php').
5. The handler retrieves the injected malicious object from the session table and passes it to the 'unserialize()' function.
6. The PHP interpreter instantiates the attacker-controlled class.
7. The application finishes processing the session data, leading to the destruction of the malicious object.
8. The object's destructor executes, writing the attacker's payload to an arbitrary path within the web root.
9. The attacker executes the newly written file via an HTTP GET request to achieve remote code execution.

## Impact

Successful exploitation of CVE-2026-80428 results in complete remote code execution as the web server user. This permits the attacker to compromise the entire ILIAS instance, access stored user data, exfiltrate sensitive academic records, and potentially gain persistence on the underlying web server hosting the application.

## Recommendation

Prioritized actions for detection and mitigation:
* Upgrade all instances of ILIAS to version 9.22, 10.10, or 11.3 immediately to remove the vulnerable logout-notification endpoint.
* Monitor web access logs for requests directed at 'shib_logout.php' originating from unauthorized or external IP addresses.
* Implement strict network segmentation to restrict access to LTI and Shibboleth authentication endpoints if not required for public-facing functionality.
