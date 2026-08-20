---
title: Russian Threat Clusters UNC6293, UNC7005, and UNC5976 Targeted OAuth and Device Code Phishing Campaigns
slug: 2026-08-russian-oauth-phishing
description: Three suspected Russian threat clusters are actively conducting targeted phishing campaigns using OAuth abuse, device code manipulation, and AitM attacks via compromised Wi-Fi gateways to hijack credentials and deploy infostealers.
date: "2026-08-20T20:18:11Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC7005
tags:
  - phishing
  - espionage
  - oauth-abuse
  - aitm
  - credential-theft
vendors:
  - Google
  - Microsoft
  - WhatsApp
products:
  - Google Cloud
  - Microsoft Entra ID
  - Microsoft 365
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The threat actor has conducted highly selective app password phishing operations aimed at individuals of interest to the Kremlin.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: The victim is sent to a Google Cloud project URL that hosts malicious scripts designed to retrieve the authentication token from the URL and stage it for later use.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: ChocoShell is a PowerShell-based infostealer that is used to steal browser session cookies.
    confidence_band: high
references:
  - https://thehackernews.com/2026/08/suspected-russian-hackers-abuse-google.html
---

Three distinct threat clusters - UNC6293, UNC7005, and UNC5976 - attributed to Russian cyber espionage interests are conducting highly targeted, adaptive phishing campaigns. These clusters focus on personnel within academia, aerospace, defense, government, and think tanks in the U.S. and Europe. The groups employ a variety of sophisticated techniques, including OAuth token theft, device code phishing against Microsoft Entra ID, and WhatsApp account linking abuse. Recent operations, such as those coordinated with the 'CaptiveCrunch' campaign, involve compromising Wi-Fi gateways to facilitate adversary-in-the-middle (AitM) attacks. Once access is gained, these actors leverage commodity infostealers like Vidar, Atomic (AMOS), and custom tooling such as the CornFlake RAT and the ChocoShell PowerShell infostealer to exfiltrate session tokens, browser data, and keystrokes. The use of lures often includes diplomatic invitations, conference registration, and file-sharing themes to induce user interaction.

## Attack Chain

1. Initial contact via spearphishing emails containing malicious links or redirection through compromised captive Wi-Fi portals (CaptiveCrunch).
2. User interacts with fake login pages (OAuth/Device Code phishing) that mimic legitimate services like Google, Microsoft, or WhatsApp.
3. Victim performs legitimate authentication, which the attacker intercepts to capture session tokens or verification codes.
4. Attacker-controlled infrastructure (often hosted on illegitimate Google Cloud projects) processes the intercepted tokens.
5. Deployment of initial-stage payloads, such as the HEADRUSH Excel plugin, HTA files, or "summit companion" applications.
6. Execution of infostealers (Vidar, Atomic) or modular RATs (CornFlake, ChocoShell) to enumerate the environment and steal session cookies/SSO tokens.
7. Exfiltration of sensitive data, surveillance recordings, and credentials to a centralized C2 panel branded as 'FruitStone'.

## Impact

Successful compromises result in unauthorized account access, theft of session tokens, and long-term espionage through the collection of keystrokes, screenshots, audio, and video recordings. Targets include high-value personnel in the defense industrial base and government sectors. The use of AitM techniques on public Wi-Fi gateways potentially impacts large numbers of users, though the targeted nature of the secondary phishing attempts suggests a focus on specific individuals of interest.

## Recommendation

* Implement FIDO2/WebAuthn-based phishing-resistant MFA for all Google and Microsoft Entra ID services to mitigate OAuth and device code phishing.
* Enforce conditional access policies that restrict logins from suspicious cloud-hosted projects or unrecognized network locations.
* Monitor for the use of suspicious Excel plugins and the execution of HTA files or PowerShell scripts associated with the 'ClickFix' lure technique.
* Advise users to exercise extreme caution when joining public Wi-Fi networks and to use organizational VPNs that enforce traffic inspection.
* Review endpoint logs for the execution of ChocoShell or CornFlake RAT activity patterns on Windows and macOS workstations.
