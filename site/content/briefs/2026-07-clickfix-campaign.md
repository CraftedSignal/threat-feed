---
brief_id: brief-2026-07-clickfix-campaign
event_id: brief-2026-07-clickfix-campaign
revision: 6
activity_at: "2026-11-13T10:15:15Z"
revision_history:
  - revision: 2
    at: "2026-10-21T13:30:22Z"
    checksum: sha256:0b81efa212888a5db4a7fa5628e1da0ca678b84dc5001fb833ed8ddd99e74a3d
    summary: new IOCs
    changed_fields:
      - cpes
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.darkreading.com/cyberattacks-data-breaches/decades-old-windows-utility-modern-clickfix-attack
  - revision: 3
    at: "2026-10-21T15:15:35Z"
    checksum: sha256:b6a019933d6460d04ca4fe4ddd338b9a92b129df5735e9caccc754fc54cd3b5a
    summary: new IOCs
    changed_fields:
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.huntress.com/blog/amazon-clickfix-finger
  - revision: 4
    at: "2026-11-05T13:35:42Z"
    checksum: sha256:9ce6cb5758477e164e39af51db8022b1586adf04f8ae6393e92c0103be5fb57e
    summary: new IOCs
    changed_fields:
      - claim_state
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://threatfox.abuse.ch/browse/malware/js.iclickfix/
  - revision: 5
    at: "2026-11-11T10:00:14Z"
    checksum: sha256:5d44dfcbe1cc70cd96d753ccd8d99cf574d773cbb0f18f1f6431d59b48d7d545
    summary: new IOCs
    changed_fields:
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
  - revision: 6
    at: "2026-11-13T10:15:15Z"
    checksum: sha256:1ae3a4b86dc3ec0a5699a72965242644cc5425297b69be7eca1389cfe4cd4fa6
    summary: exploited:true; KEV CVE-2026-110936
    changed_fields:
      - claim_state
      - exploitation_evidence
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.malware-traffic-analysis.net/2026/11/12/index.html
title: ClickFix Campaign Activity
slug: 2026-07-clickfix-campaign
description: Tracking brief for the ClickFix campaign; individual sightings are folded in as reported.
date: "2026-07-06T12:44:38Z"
lastmod: "2026-11-13T10:13:26Z"
type: threat
claim_state: verified
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-07-06T12:44:38Z"
  confidence: high
cpes:
  - cpe:2.3:a:siemens:software_center:*:*:*:*:*:*:*:*
tags:
  - campaign
  - clickfix
vendors:
  - Anthropic
  - Apple
  - axios
  - Banco do Brasil
  - Brave
  - Brazilian Government
  - Brevo
  - Calendly
  - Docker
  - Dropbox
  - Fortinet
  - GitHub
  - Google
  - JustWatch GmbH
  - MeshCentral
  - MetaMask
  - Microsoft
  - Moxa
  - Mozilla
  - NetSupport
  - Noma Labs
  - npm
  - OpenAI
  - Opera
  - Python Software Foundation
  - Siemens
  - Telegram
  - Teltonika
  - Vivaldi
  - WAGO
  - Zoom
products:
  - .gov.br municipal portals
  - .gov.br police portals
  - axios
  - Brave
  - Brevo
  - brevo.com
  - Calendly
  - Chrome
  - Chrome extensions
  - Claude
  - Docker Hub
  - DocSend
  - FortiGate
  - GitHub Actions
  - GitHub Agentic Workflows
  - GitHub AI agent
  - GitHub Copilot
  - GitHub repositories
  - Go modules
  - Google Chrome
  - Google Docs
  - Google Sheets
  - iCloud Keychain
  - macOS
  - MeshAgent
  - MetaMask
  - Microsoft Defender
  - Microsoft Edge
  - Microsoft Teams
  - Mozilla Firefox
  - NetSupport Manager
  - npm
  - NPM packages
  - open source packages
  - OpenAI ChatGPT
  - Opera
  - Opera GX
  - Packagist packages
  - PFC200
  - PyPI
  - RUTX50
  - S7-1200
  - S7-1500
  - S7-300
  - sibforms.com
  - Telegram
  - Telegram Desktop
  - Telegram Web
  - Vivaldi
  - Windows AMSI
  - Windows Defender
  - Zoom
affected_os:
  - Windows
  - macOS
cves:
  - id: CVE-2026-110936
    cvss: 6.7
    epss: 0.00967
    kev: true
    kev_status: "true"
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
  - https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_content_copied_from_browser_was_executed.yml
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/command_and_control_etherhiding_c2_via_blockchain_rpc_request.toml
  - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
  - https://blog.talosintelligence.com/clickfix-moves-into-the-browser/
  - https://www.malware-traffic-analysis.net/2026/09/11/index.html
  - https://www.securityweek.com/hacked-hbo-reddit-account-used-for-malware-delivery-via-clickfix-attack/
  - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
  - https://www.malware-traffic-analysis.net/2026/09/15/index.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_finger_exe_connecting_to_a_remote_host.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_node_exe_executing_js_script_in_immediate_folder.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_process_accessing_ironlanguages_repository_on_github.yml
  - https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites
  - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites
  - https://arcticwolf.com/resources/blog/psychedelic-stealer-fake-clickfix-captcha-targets-ukraine/
  - https://securelist.com/macsync-new-version/121383/
  - https://www.malware-traffic-analysis.net/2026/09/24/index.html
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_clickfix_runmru.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_phish_clickfix.toml
  - https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat
  - https://www.securityweek.com/hackers-use-chatgpt-custom-gpts-in-clickfix-attacks/
  - https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/
  - https://thehackernews.com/2026/09/attackers-abuse-chatgpt-custom-gpts-to.html
  - https://www.malware-traffic-analysis.net/2026/09/29/index.html
  - https://www.malware-traffic-analysis.net/2026/09/30/index.html
  - https://www.reddit.com/r/blueteamsec/comments/1x7ro0a/romulus_analysis_of_a_new_multipayload_clickfix/
  - https://www.securityweek.com/siemens-software-center-vulnerability-exploited-in-clickfix-malware-attacks/
  - https://thehackernews.com/2026/10/clickfix-attackers-exploit-siemens.html
  - https://www.darkreading.com/cyberattacks-data-breaches/decades-old-windows-utility-modern-clickfix-attack
  - https://www.huntress.com/blog/amazon-clickfix-finger
  - https://www.malware-traffic-analysis.net/2026/10/09/index.html
  - https://threatfox.abuse.ch/browse/malware/js.iclickfix/
  - https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
  - https://www.malware-traffic-analysis.net/2026/11/12/index.html
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
  - type: domain
    value: bestsocialmedianewspapper.com
  - type: domain
    value: offlineupdater.com
  - type: domain
    value: leaguejazire.com
  - type: domain
    value: riyazinikokar.xyz
  - type: domain
    value: hbomaxx.us
  - type: url
    value: http://caldav.icloud.com/published/2/MTk1NDMwMDMzNTUxOTU0M1aHCZ-nMxiyGzBTzPiodOf44DtKJ6PpjftAG28_ui2NCYMpL_vu4pF4ddsJ8ysg0QI7pR0VEIEbZYdilVZRw08
  - type: domain
    value: chatgpt.com
  - type: ip
    value: 195.63.128.106
  - type: ip
    value: 96.62.218.59
  - type: domain
    value: wizardexpensive.com
  - type: ip
    value: 2.27.248.127
  - type: domain
    value: orders-amazon.com.advancedfences.com
  - type: domain
    value: grillrecipespro.com
  - type: domain
    value: docsign.blog
  - type: domain
    value: captch.online
  - type: domain
    value: www.spgroup.com.sg
  - type: domain
    value: fudcomcheck.art
  - type: domain
    value: tsh.media
  - type: domain
    value: onchaindocfile.com
  - type: domain
    value: teal.gady-gady.com
  - type: domain
    value: ruby.gady-gady.com
  - type: domain
    value: sun.gady-gady.com
  - type: domain
    value: www.tawazon.in
  - type: domain
    value: www.stlghana.com
  - type: domain
    value: www.mslperformance.co.uk
  - type: domain
    value: nandhini-pearl.in
  - type: domain
    value: hardcontrol.ru
  - type: domain
    value: www.jacobbattista.com.au
  - type: domain
    value: atttowing.com.au
  - type: domain
    value: almarsagroup.ae
  - type: domain
    value: www.dannycasey.ie
  - type: domain
    value: sunstatehvac.com
  - type: domain
    value: spineandsportsmed.com
  - type: domain
    value: gate-air.com
  - type: domain
    value: mail.newzdex.com
  - type: domain
    value: vvestalw.ghost.io
  - type: domain
    value: westlaw-signon.com
  - type: domain
    value: cashewminaret.org
  - type: url
    value: https://cashewminaret.org/identity/reset-layout.js
  - type: url
    value: https://cashewminaret.org/identity/middleware-build?oSGDPy5P
  - type: url
    value: https://cashewminaret.org/identity/gateway-dom.js?18e76625db12fb1d
  - type: url
    value: https://orchardandbarite.com/spa
  - type: url
    value: https://orchardandbarite.com/gross
  - type: hash_sha256
    value: 2eb387df728fc6f5dd2dcffaf1883cbf8c5e0c489f6cb38021d67f856ee669d0
  - type: hash_sha256
    value: 101e9ac653ccd341e36fae84a5c6920dff47a41822e87db4c72e36da4830d707
  - type: ip
    value: 87.199.205.61
ioc_counts:
  domain: 47
  hash_sha256: 3
  ip: 6
  url: 14
updates:
  - at: "2026-10-21T13:29:50Z"
    level: L1
    summary: new IOCs
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/cyberattacks-data-breaches/decades-old-windows-utility-modern-clickfix-attack
  - at: "2026-10-21T14:21:30Z"
    level: L1
    summary: new IOCs
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/amazon-clickfix-finger
  - at: "2026-11-05T13:32:00Z"
    level: L1
    summary: new IOCs
    sources:
      - abuse-ch
    source_urls:
      - https://threatfox.abuse.ch/browse/malware/js.iclickfix/
  - at: "2026-11-11T09:59:15Z"
    level: L1
    summary: new IOCs
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
  - at: "2026-11-13T10:13:26Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-110936
    sources:
      - malware-traffic-analysis
    source_urls:
      - https://www.malware-traffic-analysis.net/2026/11/12/index.html
---

This brief tracks activity attributed to the ClickFix campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for ClickFix delivery
patterns across endpoint and network telemetry.
