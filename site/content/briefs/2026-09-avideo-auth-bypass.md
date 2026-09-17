---
title: Authentication Bypass in AVideo LoginControl via PGP Verification
slug: 2026-09-avideo-auth-bypass
description: An authentication bypass vulnerability in AVideo LoginControl allows attackers with a victim's password to circumvent PGP two-factor authentication by exploiting loose equality checks.
date: "2026-09-17T13:56:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:avideo:logincontrol:*:*:*:*:*:*:*:*
vendors:
  - AVideo
products:
  - LoginControl
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers with a victim's password can bypass the second factor by sending a parameter-less GET request to verifyChallenge.json.php.
    confidence_band: high
cves:
  - id: CVE-2026-92914
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92914
rules:
  - title: Detect CVE-2026-92914 Exploitation - Unauthenticated AVideo Authentication Bypass
    description: Detects exploitation of CVE-2026-92914 by monitoring for GET requests to verifyChallenge.json.php that lack required query parameters, potentially triggering the loose equality authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for parameter-less access to verifyChallenge.json.php
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies the vulnerable endpoint and exploitation method
  hunt_leads:
    - lead: Search logs for successful logins to AVideo that coincide with parameter-less requests to verifyChallenge.json.php
      technique_id: T1550.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation logic requires access to this specific endpoint
  mitigation_plan:
    - priority: immediate
      action: Identify and disable PGP-based 2FA if patching is not immediately available
      owner: IT Operations
      addresses: CVE-2026-92914
      evidence: Authentication bypass vulnerability identified in PGP secondary factor logic
---

AVideo LoginControl contains an authentication bypass vulnerability within its PGP second-factor verification process. The vulnerability stems from an insecure implementation of challenge response verification that uses loose equality comparison (==) against an uninitialized session variable. Because the code evaluates an uninitialized session variable as null, an attacker possessing a victim's account password can trigger this bypass by submitting a parameter-less GET request to the 'verifyChallenge.json.php' endpoint. This results in a condition where the check evaluates null == null, allowing the system to erroneously mark the second-factor authentication as complete. This flaw grants unauthorized access to accounts that have PGP-based multi-factor authentication enabled, effectively negating the security controls intended to protect these identities. Defenders should identify instances of AVideo LoginControl and monitor web server access logs for anomalous requests to the identified verification endpoint.

## Impact

Successful exploitation of CVE-2026-92914 allows unauthenticated actors who have obtained valid user credentials to bypass second-factor authentication controls. This leads to unauthorized account access, potential data exfiltration, and persistence within the application environment. The severity is assessed as high due to the bypass of critical authentication controls in enterprise media management workflows.

## Recommendation

- Deploy the provided Sigma rule to detect suspicious access to the vulnerable verification endpoint.
- Review web server logs for requests to 'verifyChallenge.json.php' that lack expected parameters or authentication headers.
- Identify all instances of AVideo LoginControl within the environment and coordinate with the vendor or upstream project for available security patches.
