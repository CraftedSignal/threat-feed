---
title: Phishing Campaign Leveraging Blob URLs and Microsoft Teams Redirects
slug: 2026-09-blob-url-phishing
description: Threat actors are using legitimate Microsoft Teams redirects to chain external resources and generate dynamic, browser-resident phishing pages via blob URLs to bypass static URL scanning.
date: "2026-09-09T10:52:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - browser-security
  - credential-theft
  - microsoft-teams
vendors:
  - Microsoft
products:
  - Microsoft Teams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: It starts with a Docusign-themed email with an attached calendar invite.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The attack flow is similar to standard phishing since the victim must be steered to an external resource.
    confidence_band: high
references:
  - https://www.securityweek.com/new-phishing-attack-creates-malicious-pages-inside-the-victims-browser/
iocs:
  - type: domain
    value: cdn.bloom.io
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block cdn.bloom.io at the enterprise proxy and DNS level.
      owner: SOC
      due: 24h
      evidence: Source explicitly identifies this as the external resource trigger.
  enrichment_needed:
    - item: cdn.bloom.io reputation
      owner: CTI
      reason: Assess if this domain is consistently used for malicious activity.
      evidence: Source reporting
  hunt_leads:
    - lead: Search proxy logs for HTTP Referer headers indicating navigation from Microsoft Teams to cdn.bloom.io.
      technique_id: T1566.002
      data_needed:
        - Proxy/Web logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A crafted redirect routes the user to Microsoft Teams, which then loads an external resource hosted on cdn.bloom.io.
  mitigation_plan:
    - priority: short_term
      action: Review email security filtering policies for calendar invites and external URL redirects.
      owner: IT Operations
      addresses: Phishing delivery
      evidence: Source notes redirect obfuscation through trusted processes.
---

A novel phishing campaign identified in September 2026 utilizes legitimate Microsoft services to deliver malicious content without the use of static, hosted phishing pages. The attack leverages Microsoft Teams as a trusted conduit to redirect victims to an external resource hosted on cdn.bloom.io. Once the victim is navigated to this resource, the browser dynamically generates a blob URL, which renders a full phishing interface directly within the user's session.

By utilizing blob URLs and browser-native rendering, the phishing interface exists entirely within the victim's memory, evading traditional email security gateways and URL scanning tools that rely on static analysis of domain content. The attack utilizes service workers, iframes, and backend controls to manage user interaction, effectively creating a centrally managed, platform-based phishing workflow that can be updated in real-time. This technique prioritizes stealth by embedding the delivery mechanism within trusted Microsoft infrastructure.

## Attack Chain

1. Attacker sends a spearphishing email with a Docusign-themed message and a calendar invite attachment.
2. The email contains a link that initiates a redirect sequence through legitimate Microsoft services, specifically Microsoft Teams.
3. The redirect routes the user to an attacker-controlled external resource hosted on cdn.bloom.io.
4. The browser executes scripts from the external resource to generate a dynamic blob URL (e.g., blob:https://...).
5. The blob URL renders a phishing interface inside the victim's browser session.
6. Service workers and iframes are initialized to maintain the session and manage the navigation flow.
7. Interaction data and credentials are exfiltrated via backend controls managed by a central command-and-control platform.

## Impact

This campaign represents a significant shift in phishing delivery by eliminating the physical landing page typically used by security controls for blocking and reputation analysis. By leveraging trusted infrastructure (Microsoft Teams) and dynamic client-side rendering (blob URLs), attackers significantly increase the success rate of credential harvesting. This technique enables attackers to update phishing interfaces in real-time without hosting new domains, complicating long-term detection and takedown efforts.

## Recommendation

1. Implement advanced browser security controls that inspect and restrict the creation of blob URLs from untrusted or low-reputation third-party domains.
2. Enhance email security gateways to perform full-path analysis and behavioral execution of URLs rather than relying on static categorization of initial landing domains.
3. Monitor OAuth authorization flows and web proxy logs for unexpected destinations triggered immediately following navigation to Microsoft services, specifically looking for traffic patterns leading to cdn.bloom.io.
4. Educate users on the risks associated with calendar invites and redirects emanating from trusted collaboration platforms.
5. Deploy behavioral detection rules for unusual browser service worker activity associated with suspicious redirection chains.
