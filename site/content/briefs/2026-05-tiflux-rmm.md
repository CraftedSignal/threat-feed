---
title: Tiflux RMM Abused in Malspam Campaign
slug: 2026-05-tiflux-rmm
description: A malspam campaign is leveraging the Tiflux RMM to gain remote access and persistence on victim machines, abusing legitimate remote management software for stealthy access and persistence.
date: "2026-05-14T21:01:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-access
  - rmm
  - malspam
  - persistence
vendors:
  - Tiflux
  - Microsoft
  - Splashtop
  - ScreenConnect
  - UltraVNC
products:
  - Tiflux
  - UltraVNC
  - Splashtop
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.huntress.com/blog/tiflux-rmm-install
iocs:
  - type: domain
    value: hg[.]lawdepotisland[.]com
  - type: domain
    value: lenwillfilenetwork[.]com
ioc_counts:
  domain: 2
rules:
  - title: Detect Tiflux RMM Installation via MSI
    description: Detects the installation of Tiflux RMM based on the MSI installer file name and publisher.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect UltraVNC Installation
    description: Detects silent installations of UltraVNC.
    platform: sigma
    severity: medium
    tactics:
      - remote_access
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A malspam campaign has been observed utilizing Tiflux, a commercial RMM tool, to gain unauthorized access and maintain persistence within victim environments starting around February 2026. The campaign employs phishing emails containing fake document lures, ultimately leading to the installation of Tiflux alongside other remote administration tools, including UltraVNC, Splashtop, and ScreenConnect. What makes this campaign particularly concerning is the inclusion of outdated and potentially vulnerable components within the Tiflux installer, such as the HwRwDrv.sys driver, which is associated with privilege elevation and signed using expired certificates. Huntress has observed an increase in Tiflux usage across various incidents, indicating a trend of threat actors experimenting with RMMs for stealthy access.

## Attack Chain

1. A phishing email, appearing to be a business service agreement, is sent from `businessservices@hg[.]lawdepotisland[.]com`.
2. The email contains a link that redirects the victim to a page hosted on `lenwillfilenetwork[.]com` protected by a Cloudflare CAPTCHA to filter out automated analysis.
3. Upon successful CAPTCHA completion, the victim is redirected to a page prompting them to download a "secured document."
4. Clicking the download link retrieves an MSI installer named "Network Solutions Agreement.msi", which is cryptographically signed by "Tiflux Sistema de Gestão LTDA".
5. The MSI installer extracts and installs various Tiflux components, including `TiAgent.exe` (the main RMM orchestrator) and `TiPeerToPeer.exe` (a backchannel communication tool).
6. The installer also deploys silent installers for third-party dependencies such as UltraVNC and compression utilities 7zip and tar, expanding remote access capabilities.
7. The threat actor establishes persistence on the system using the installed RMM tools.
8. Using the RMM access, the attacker performs unauthorized access and credential theft, profiling the system and transmitting screenshots.

## Impact

Successful exploitation leads to the establishment of unauthorized remote access, persistent control, and potential data theft from compromised systems. The use of Tiflux alongside other remote administration tools such as UltraVNC, Splashtop, and ScreenConnect amplifies the impact. The inclusion of a vulnerable driver may lead to privilege escalation, enabling attackers to perform more invasive actions on the compromised host. The number of impacted Huntress customers is unknown, but the increased use of Tiflux since February 2026 indicates a growing threat.

## Recommendation

*   Deploy the Sigma rule "Detect Tiflux RMM Installation via MSI" to identify potential installations of the Tiflux RMM based on the MSI installer file name and publisher.
*   Block the domains `hg[.]lawdepotisland[.]com` and `lenwillfilenetwork[.]com` at the network perimeter to prevent initial access via the observed malspam campaign.
*   Monitor process creation events for execution of `TiAgent.exe` and `TiPeerToPeer.exe`, core components of the Tiflux RMM, and investigate any suspicious instances.
*   Implement application control policies to prevent the execution of unsigned or untrusted executables in user directories, mitigating the risk of malicious software execution.
*   Deploy the Sigma rule "Detect UltraVNC Installation" to identify silent installations of UltraVNC.
