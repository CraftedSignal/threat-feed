---
title: ClickFix Campaign Activity
slug: 2026-07-clickfix-campaign
description: Tracking brief for the ClickFix campaign; individual sightings are folded in as reported.
date: "2026-07-06T12:44:38Z"
lastmod: "2026-08-29T09:10:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - campaign
  - clickfix
vendors:
  - GitHub
  - Google
  - Noma Labs
  - Anthropic
  - JustWatch GmbH
  - Microsoft
  - Telegram
  - Brazilian Government
  - Banco do Brasil
  - Apple
  - Zoom
  - Calendly
  - Brave
  - Mozilla
  - Opera
  - Vivaldi
  - MetaMask
  - OpenAI
  - Docker
  - Python Software Foundation
  - npm
  - axios
  - Fortinet
  - Teltonika
  - WAGO
  - Siemens
  - Moxa
  - Dropbox
products:
  - open source packages
  - GitHub repositories
  - NPM packages
  - Packagist packages
  - Go modules
  - Chrome extensions
  - GitHub Agentic Workflows
  - GitHub AI agent
  - GitHub Actions
  - GitHub Copilot
  - Claude
  - Windows Defender
  - Windows AMSI
  - Telegram
  - .gov.br municipal portals
  - .gov.br police portals
  - macOS
  - Zoom
  - Microsoft Teams
  - Calendly
  - Telegram Web
  - Telegram Desktop
  - Google Chrome
  - Microsoft Edge
  - Brave
  - Mozilla Firefox
  - Opera
  - Opera GX
  - Vivaldi
  - MetaMask
  - iCloud Keychain
  - Microsoft Defender
  - OpenAI ChatGPT
  - PyPI
  - npm
  - Docker Hub
  - axios
  - FortiGate
  - RUTX50
  - PFC200
  - S7-300
  - S7-1200
  - S7-1500
  - Google Docs
  - DocSend
affected_os:
  - Windows
  - macOS
references:
  - https://www.securityweek.com/north-korean-hackers-target-open-source-developers-in-supply-chain-attacks/
  - https://hackread.com/gitlost-github-ai-agent-leaking-repository-data/
  - https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/
  - https://www.reddit.com/r/blueteamsec/comments/1uxuh7t/telepuz_a_modular_maas_malware_spreading_via/
  - https://any.run/cybersecurity-blog/phantomenigma-research/
  - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
  - https://www.securityweek.com/clicklock-stealer-bypasses-macos-security-with-social-engineering-process-killing/
  - https://thehackernews.com/2026/07/bluenoroff-zoom-phishing-kit-profiles.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_fakecaptcha_clipboard_execution.yml
  - https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise/
  - https://www.malware-traffic-analysis.net/2026/07/31/index.html
  - https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/
  - https://thehackernews.com/2026/08/hackers-breach-polish-power-plant.html
  - https://www.malware-traffic-analysis.net/2026/08/12/index.html
  - https://www.securityweek.com/amnesiastealer-macos-malware-steals-data-controls-browser-sessions/
  - https://www.reddit.com/r/blueteamsec/comments/1vpaaqu/amnesiastealer_macos_infostealer_that_hijacks/
  - https://thehackernews.com/2026/08/amnesiastealer-hijacks-chromium.html
  - https://www.huntress.com/blog/mac-crypto-draining-malware
  - https://thehackernews.com/2026/08/microsoft-links-30-rotating-domains-to.html
  - https://thehackernews.com/2026/08/stopandprotect-uses-nearly-2000-hacked.html
  - https://www.malware-traffic-analysis.net/2026/08/21/index.html
  - https://www.huntress.com/blog/defcon-phishing-google-doc-malware
  - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
iocs:
  - type: domain
    value: justwatch.com
  - type: ip
    value: 136.243.203.109
  - type: domain
    value: pool.supportxmr.com
  - type: domain
    value: ip-api.com
  - type: domain
    value: .gov.br
  - type: domain
    value: us.zoom.06webin.us
  - type: url
    value: https://pewtercanto.top/user/throttle-effect.js
  - type: url
    value: https://pewtercanto.top/user/acl-dom?JSMlAATp
  - type: url
    value: https://pewtercanto.top/user/version-deploy.js?18c7713e5fb5a572
  - type: url
    value: http://deltaode.com/po
  - type: domain
    value: apricotfilepoint.com
  - type: domain
    value: filecopperbasket.com
  - type: domain
    value: filevelvettractor.com
  - type: domain
    value: fileoceanhammer.com
  - type: domain
    value: filemarblegarden.com
  - type: domain
    value: debug.allllowef.space
  - type: ip
    value: 193.29.224.151
  - type: domain
    value: rowanportico.global
  - type: url
    value: https://rowanportico.global/identity/realm-xml.js
  - type: url
    value: https://rowanportico.global/identity/role-template?xPM7XYCZ
  - type: url
    value: https://rowanportico.global/identity/secure-theme.js?18cddb5baf41fce0
  - type: url
    value: http://lagoonandledger.com/crol
  - type: domain
    value: gitnow.dev
  - type: hash_sha256
    value: 18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f
ioc_counts:
  domain: 13
  hash_sha256: 1
  ip: 2
  url: 8
updates:
  - at: "2026-08-17T11:47:09Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/08/amnesiastealer-hijacks-chromium.html
  - at: "2026-08-18T20:50:59Z"
    level: L1
    summary: new IOCs
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/mac-crypto-draining-malware
  - at: "2026-08-22T01:12:10Z"
    level: L1
    summary: new IOCs
    sources:
      - malware-traffic-analysis
    source_urls:
      - https://www.malware-traffic-analysis.net/2026/08/21/index.html
  - at: "2026-08-26T00:48:44Z"
    level: L1
    summary: new product
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/defcon-phishing-google-doc-malware
  - at: "2026-08-29T09:10:33Z"
    level: L1
    summary: new IOCs
    sources:
      - microsoft-threat-intel
    source_urls:
      - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
---

This brief tracks activity attributed to the ClickFix campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for ClickFix delivery
patterns across endpoint and network telemetry.
