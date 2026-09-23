---
title: OAuth Token Theft via Sideloaded AppX and WWAHost.exe
slug: 2026-09-oauth-token-theft
description: Attackers can abuse sideloaded AppX packages and the legitimate WWAHost.exe binary to trigger a genuine Microsoft OAuth login flow, capturing valid authentication tokens without traditional phishing indicators.
date: "2026-09-23T14:04:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth-theft
  - living-off-the-land
  - windows
  - sideloading
vendors:
  - Microsoft
products:
  - Windows (11 24H2 and later)
affected_os:
  - Windows 11
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A sideloaded AppX package abuses Microsoft-signed AppX web hosts to present a legitimate Microsoft sign-in and capture the resulting OAuth tokens.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A second later the access token and the refresh token were sitting in my listener.
    confidence_band: high
rules:
  - title: Detect Suspicious AppModelUnlock Registry Modification
    description: Detects the modification of the AppModelUnlock registry key, which enables sideloading of unsigned AppX packages and is a prerequisite for this attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1552.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit endpoint configuration for 'Developer Mode' status and disable on production workstations.
      owner: IT Operations
      due: 48h
      evidence: 'Source states: This setting is the real exposure gate.'
  hunt_leads:
    - lead: Search network logs for the 'MSAppHost/3.0' user agent connecting to non-Microsoft domains.
      technique_id: T1204.002
      data_needed:
        - Proxy or Firewall logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Detection is a network problem: watch for the MSAppHost/3.0 user agent reaching non-Microsoft destinations.'
---

This threat involves the exploitation of the Windows Web App Host (WWAHost.exe) to facilitate OAuth token theft. By sideloading a maliciously crafted, unsigned AppX package onto a Windows machine with 'Developer Mode' or enterprise sideloading policies enabled, an attacker can manipulate WWAHost.exe to render remote JavaScript that interacts with the WebAuthenticationBroker API. Because the process is a signed Microsoft binary and the authentication dialog is served directly from login.microsoftonline.com, the flow is entirely authentic. The victim completes a legitimate MFA process, providing the attacker with valid access and refresh tokens that bypass typical phishing defenses. This technique is highly effective as it avoids malicious domains, spoofed UIs, and certificate warnings, relying instead on the trust established by Microsoft's own signed binaries.

## Attack Chain

1. Attacker ensures the target host has 'Developer Mode' enabled via registry modification (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock) or system settings.
2. Attacker deploys a malicious, unsigned AppX package to the target endpoint using `Add-AppxPackage -Register`.
3. AppX package is configured with a manifest declaring `WindowsRuntimeAccess="all"` to gain access to the Windows Runtime API.
4. WWAHost.exe executes the package, rendering remote content provided by the attacker's infrastructure.
5. The rendered content invokes the `WebAuthenticationBroker` API, passing a legitimate client ID (e.g., for Microsoft Office).
6. WWAHost.exe launches a genuine Microsoft login dialog, authenticating the user against Microsoft servers without browser artifacts.
7. Upon successful MFA, the attacker's listener captures the issued access and refresh tokens for subsequent unauthorized M365 data access.

## Impact

Successful exploitation results in the exfiltration of durable refresh tokens, granting persistent access to the victim's Microsoft 365 environment. The scope of impact scales with the privileges assigned to the compromised user, potentially allowing for business email compromise, data exfiltration, or further lateral movement within the cloud identity environment.

## Recommendation

Prioritize the identification and restriction of developer settings on endpoint devices.

* Audit the 'Developer Mode' setting across the enterprise fleet and disable it on all workstations where it is not strictly required for development workflows.
* Monitor for the registration of new, unsigned AppX packages via event logs (e.g., AppxPackaging/Operational logs).
* Implement network monitoring to detect the 'MSAppHost/3.0' user agent when it initiates connections to non-Microsoft domains or suspicious external infrastructure.
* Configure SIEM alerts for the modification of the AppModelUnlock registry key, which is a prerequisite for this attack chain.
