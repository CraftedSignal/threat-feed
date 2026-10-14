---
title: Credential Harvesting via Lookalike WatchGuard VPN Download Sites
slug: 2026-10-fake-watchguard-vpn
description: Threat actors are using typosquatted domains to harvest WatchGuard VPN credentials via fake portals before delivering legitimate software to maintain victim trust.
date: "2026-10-14T10:17:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-harvesting
  - typosquatting
  - vpn
  - watchguard
vendors:
  - WatchGuard
products:
  - Mobile VPN with SSL
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The malicious website used a browser pop-up prompt to steal the victim's VPN server address, username, and password.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1566
    technique_name: Phishing
    evidence: A simple search on Google or Bing for a VPN client download may seem like a run-of-the-mill task, but it can also expose users to convincing credential phishing sites.
    confidence_band: high
references:
  - https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing
iocs:
  - type: domain
    value: watchguard-vpn.net
  - type: domain
    value: watchguard-ssl.online
ioc_counts:
  domain: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block watchguard-vpn.net and watchguard-ssl.online at the perimeter DNS/proxy.
      owner: SOC
      due: 24h
      evidence: Identified malicious infrastructure.
  hunt_leads:
    - lead: Search proxy logs for any outbound traffic to watchguard-vpn.net or watchguard-ssl.online.
      technique_id: T1566
      data_needed:
        - Proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Domains identified as credential harvesting infrastructure.
---

In October 2026, researchers observed a credential-harvesting campaign targeting WatchGuard Mobile VPN with SSL users. The threat actors leveraged lookalike domains, specifically 'watchguard-vpn.net', to present users with a fraudulent 'WatchGuard Firebox VPN Client' portal after they performed search engine queries for VPN software. The attack is designed to appear legitimate; after victims enter their VPN server address, username, and password, the site rejects the first entry - likely to prompt a second, verified set of credentials - and subsequently initiates the download of a genuine, legitimately signed installer directly from WatchGuard's official content delivery network. By serving a benign, signed binary after credential theft, the actors successfully bypass traditional signature-based endpoint detection tools while maintaining the victim's trust. The infrastructure involved in this campaign includes domains registered as recently as August and September 2026.

## Attack Chain

1. Attacker registers typosquatted domains (e.g., watchguard-vpn.net) and performs SEO poisoning to elevate site rankings in search results.
2. Victim searches for VPN software on search engines and clicks the malicious link.
3. Victim is directed to a spoofed download portal styled as the official WatchGuard VPN client page.
4. Victim is prompted via browser pop-up or modal to input VPN server address, username, and password.
5. Attacker server collects credentials, potentially rejecting the first submission to force a second entry.
6. Attacker server triggers a download of the genuine, validly signed WatchGuard installer from the official vendor CDN.
7. Attacker utilizes the harvested credentials to gain unauthorized access to the victim's corporate network.

## Impact

The primary impact is the unauthorized acquisition of VPN credentials, which grants attackers broad access to victim networks. Because the final file delivered is a legitimate, signed application, there is no malware payload for traditional endpoint detection and response (EDR) agents to flag, increasing the dwell time for threat actors who gain initial access via the stolen VPN credentials.

## Recommendation

- Implement DNS filtering to block traffic to known lookalike domains including 'watchguard-vpn.net' and 'watchguard-ssl.online'.
- Monitor web traffic logs for employees navigating to non-official domains that mimic vendor download pages.
- Enforce multi-factor authentication (MFA) for all VPN access to render harvested credentials useless.
- Conduct security awareness training focusing on verifying URLs before downloading software or entering corporate credentials.
- Review historical VPN logs for anomalous authentication patterns or geographic inconsistencies following potential exposure to these domains.
