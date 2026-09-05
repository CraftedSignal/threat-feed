---
title: Entra ID PRT Extraction via BrowserCore.exe Abuse
slug: 2026-09-entraid-prt-extraction
description: Adversaries are abusing the legitimate BrowserCore.exe component to perform unauthorized extraction of Entra ID Primary Refresh Tokens (PRTs) by invoking the binary outside of expected browser-managed contexts.
date: "2026-09-05T00:00:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - browser-security
  - windows
  - session-hijacking
vendors:
  - Microsoft
products:
  - Microsoft Edge
  - Google Chrome
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Adversaries abuse BrowserCore to extract Entra ID Primary Refresh Tokens (PRTs) without interactive browser context, enabling session hijacking.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: Adversaries abuse BrowserCore to extract Entra ID Primary Refresh Tokens (PRTs) without interactive browser context, enabling session hijacking.
    confidence_band: high
rules:
  - title: Detect Potential Entra ID PRT Extraction via BrowserCore
    description: Detects anomalous execution of BrowserCore.exe where the process is launched without the required chrome-extension:// native-messaging argument.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1528
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy provided detection rule for BrowserCore.exe abuse.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting anomalous BrowserCore execution.
  hunt_leads:
    - lead: Search for BrowserCore.exe processes spawned by non-browser parent processes.
      technique_id: T1528
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: BrowserCore.exe abuse is linked to non-interactive launching by scripts or tasks.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict permission for non-browser processes to invoke BrowserCore.exe.
      owner: IT Operations
      addresses: T1528
      evidence: Source highlights BrowserCore as a target for direct process invocation.
---

BrowserCore.exe is a native-messaging helper component used by Chromium-based browsers like Microsoft Edge and Google Chrome to broker communications between the browser and the Windows Web Account Manager (WAM). This component facilitates single sign-on (SSO) and Entra ID authentication operations. Threat actors have been observed abusing BrowserCore.exe to perform unauthorized extraction of Entra ID Primary Refresh Tokens (PRTs).

By invoking BrowserCore.exe directly - bypassing the browser's native-messaging host context - attackers can interact with WAM to export sensitive session tokens. Legitimate browser-initiated calls to BrowserCore.exe are always accompanied by a specific command-line argument containing a 'chrome-extension://' URI. Adversaries utilize tools like PRTRemote and PrtExtractor to execute the binary without this required argument, allowing for silent token harvesting that facilitates session hijacking and persistent access to cloud resources. Defenders should monitor for BrowserCore.exe processes spawned by non-browser parent processes or those missing the expected extension argument.

## Attack Chain

1. Attacker gains initial access to the target Windows endpoint.
2. Attacker drops credential theft tools such as PRTRemote or PrtExtractor onto the local disk.
3. Attacker establishes persistence or triggers execution via a scheduled task, malicious script, or manual command-line execution.
4. The malicious script or tool spawns 'BrowserCore.exe' as a child process.
5. The attacker executes the process without the legitimate 'chrome-extension://' command-line argument.
6. The process interacts with the Windows Web Account Manager (WAM) via the native-messaging interface.
7. The tool exfiltrates the Primary Refresh Token (PRT) from the WAM store.
8. Attacker uses the stolen PRT to perform session hijacking or unauthorized access to Entra ID-protected applications.

## Impact

Successful exploitation results in the theft of Entra ID Primary Refresh Tokens (PRTs), allowing attackers to bypass multi-factor authentication (MFA) and conditional access policies. This enables persistent unauthorized access to the victim's cloud-based accounts and corporate resources until the compromised tokens are revoked or credentials are rotated.

## Recommendation

- Implement the detection rule provided below to identify anomalous executions of BrowserCore.exe.
- Prioritize investigation of BrowserCore.exe processes spawned by unexpected parent processes (e.g., cmd.exe, powershell.exe, wscript.exe, or svchost.exe/scheduled tasks).
- Verify that all legitimate executions of BrowserCore.exe contain the 'chrome-extension://' URI in the command-line arguments.
- If token extraction is confirmed, perform an immediate incident response: isolate the host, revoke all active Entra ID refresh tokens for the affected user, and mandate a credential rotation.
- Hunt for the presence of known credential extraction tools (e.g., PRTRemote, PrtExtractor) across the endpoint fleet using file hash and path telemetry.
