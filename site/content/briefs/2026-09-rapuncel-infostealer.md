---
title: Rapuncel Infostealer Campaign Impersonates Software Brands
slug: 2026-09-rapuncel-infostealer
description: The Rapuncel infostealer campaign uses SEO-poisoned GitHub repositories to deliver malicious installers that deploy a kernel-level EDR killer to disable security products and harvest sensitive data.
date: "2026-09-21T16:25:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - infostealer
  - malware
  - persistence
  - defense-evasion
  - supply-chain
vendors:
  - Microsoft
  - LastPass
products:
  - LastPass Authenticator
  - LastPass (macOS installer)
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Using SEO optimization, the attackers’ GitHub page serving the fraudulent LastPass Authenticator was shown among the top results to users searching for the legitimate application.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: the attackers impersonated at least 40 organizations to push a Microsoft-attested kernel driver designed to terminate 145 security tools
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The malware installs itself as a Windows service that starts automatically every time the computer boots.
    confidence_band: high
rules:
  - title: Detect Suspicious Service Creation by Untrusted Binaries
    description: Detects the creation of new Windows services that may indicate persistence for malware like Rapuncel.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
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
    - action: Review GitHub access logs for anomalous traffic patterns
      owner: SOC
      due: 24h
      evidence: Victims routed through multiple GitHub pages
  hunt_leads:
    - lead: Search for unsigned services with ImagePath in non-standard directories (e.g., C:\Users\Public\)
      technique_id: T1547
      data_needed:
        - Endpoint process and service creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware installs itself as a Windows service
  mitigation_plan:
    - priority: immediate
      action: Strictly enforce the use of official vendor download portals and prohibit downloading software from public repository hosting sites
      owner: IT Operations
      addresses: Initial access vector via GitHub
      evidence: Attackers impersonated at least 40 companies on GitHub
---

Since at least August 2026, threat actors have conducted a broad brand-impersonation campaign using SEO-poisoning techniques on GitHub to distribute fake software installers, including fraudulent LastPass Authenticator and macOS LastPass applications. The campaign, which targets at least 40 organizations, relies on a complex redirect chain involving GitHub and Cloudflare to deliver malicious archives. Upon execution, the installer uses a side-loaded DLL to deploy a Microsoft-attested kernel driver disguised as an NVIDIA component. This driver is designed to terminate 145 different endpoint security and antivirus products. Once security defenses are neutralized, the 'Rapuncel' stealer module installs itself as a persistent Windows service to harvest browser credentials, cryptocurrency wallets, messaging tokens, and system profile data. Researchers have identified links between this campaign's DLL loaders and the Cruciferra crypter service, as well as behavioral overlaps with the BoryptGrab infostealer.

## Attack Chain

1. The victim performs a search engine query and navigates to an SEO-poisoned GitHub repository masquerading as a legitimate software provider.
2. The victim clicks a download link that traverses a hidden routing chain via multiple GitHub pages and a Cloudflare-fronted server.
3. The victim downloads a malicious archive containing a fake installer and a companion DLL, which acts as a side-loader for malicious code.
4. The installer executes a renamed legitimate debugging tool, which triggers the side-loading of the companion DLL into memory.
5. The attacker's code loads a Microsoft-attested kernel driver that hides itself and attempts to terminate 145 predefined security and antivirus processes.
6. The malware installs itself as a Windows service to ensure persistence across system reboots.
7. The Rapuncel module scans the file system for sensitive data, including cryptocurrency wallets, browser-stored passwords, and messaging tokens.
8. Captured data and system profiles are exfiltrated to the attacker's infrastructure while the service remains active to monitor and re-kill any restarted security tools.

## Impact

This campaign poses a severe risk to corporate and personal data by disabling endpoint security protections to facilitate long-term unauthorized access. By targeting 40+ brands and 145 security products, the attackers aim to harvest high-value credentials, cryptocurrency, and session tokens from a wide victim base. Successful infection results in total system compromise, where the machine remains under attacker control until the kernel-level driver is manually removed.

## Recommendation

Prioritize detection and response efforts to identify unauthorized kernel driver loads and persistent service creation associated with this campaign.

- Monitor endpoint logs for the installation of unsigned or suspiciously named kernel drivers, particularly those attempting to spoof NVIDIA-related file paths.
- Enable Sysmon or equivalent EDR telemetry to detect the execution of renamed debugging tools (e.g., binaries performing DLL side-loading).
- Inspect GitHub-sourced software downloads for unauthorized or misaligned branding, especially when hosted outside of official vendor domains.
- Deploy detection rules to identify new Windows services that lack verifiable developer signatures or that exhibit suspicious file paths in the ImagePath property.
