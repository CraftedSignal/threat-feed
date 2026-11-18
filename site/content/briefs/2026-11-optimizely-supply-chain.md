---
brief_id: brief-2026-11-17-optimizely-supply-chain
event_id: brief-2026-11-17-optimizely-supply-chain
revision: 2
activity_at: "2026-11-18T07:01:58Z"
revision_history:
  - revision: 2
    at: "2026-11-18T07:01:58Z"
    checksum: sha256:0d5d850134e9d28c0c64a90079a1e0d064aedfbb1c7c5598236e72c477b731aa
    summary: added coverage for Optimizely website personalization platform
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - content
      - iocs
      - lastmod
      - priority_signals
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://arstechnica.com/security/2026/11/malicious-code-delivered-through-optimizely-hits-visitors-to-hundreds-of-sites/
title: 'Optimizely: Malicious JavaScript injection via compromised platform infrastructure'
slug: 2026-11-optimizely-supply-chain
description: Attackers compromised the Optimizely website personalization platform to distribute malicious JavaScript across hundreds of client websites, enabling cryptocurrency theft, payment card skimming, and the delivery of iOS exploit kits.
date: "2026-11-17T20:54:45Z"
lastmod: "2026-11-18T07:01:26Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.sophos.com/en-us/blog/hijacked-optimizely-snippets-served-malicious-code
  observed_at: "2026-11-16T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against Sophos X-Ops advisory.
tags:
  - supply-chain
  - web-application
  - js-injection
  - javascript-injection
  - malware
  - web
vendors:
  - Optimizely
products:
  - Optimizely website personalization platform
  - Web Experimentation
affected_os:
  - iOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: On November 17, 2026, Optimizely reported that an attacker exploited a vulnerability in its Web Experimentation product to add malicious JavaScript to some customer projects.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: Third-party reporting indicates that the code was injected into snippets belonging to 178 organizations, including CNN, the BBC, and Zoom, on November 16.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Hundreds of websites using the Optimizely website personalization platform served unsuspecting visitors a potent malware cocktail.
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/hijacked-optimizely-snippets-served-malicious-code
  - https://arstechnica.com/security/2026/11/malicious-code-delivered-through-optimizely-hits-visitors-to-hundreds-of-sites/
  - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
iocs:
  - type: url
    value: https://1688360.cc/card.php
  - type: url
    value: https://1688360.cc/hit.php
  - type: domain
    value: 5vobauua3ojpklx.icu
  - type: domain
    value: eil786npto9u5bq.icu
ioc_counts:
  domain: 2
  url: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Check Optimizely Web Experimentation projects for code injected on November 16, 2026.
      due: immediate
      evidence: Organizations using Optimizely Web Experimentation should check their projects for code injected on November 16
    - action: Block identified malicious domains and URLs at the network perimeter
      owner: SOC
      due: 1h
      evidence: Ars Technica report citing attacker-controlled infrastructure
  hunt_leads:
    - lead: Identify unauthorized modifications to external-facing JavaScript snippets or experiment configurations within the Optimizely platform dashboard or audit logs initiated on or around November 16, 2026.
      technique_id: T1190
      data_needed:
        - Optimizely Audit Logs
        - Change Management Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: On November 17, 2026, Optimizely reported that an attacker exploited a vulnerability in its Web Experimentation product to add malicious JavaScript to some customer projects.
    - lead: Perform a retrospective analysis of web traffic and Content Security Policy (CSP) violation reports to detect execution of unrecognized or unauthorized JavaScript snippets loaded from Optimizely-hosted resources on websites.
      technique_id: T1059
      data_needed:
        - Web Application Firewall logs
        - Content Security Policy (CSP) violation reports
        - Browser telemetry/client-side monitoring
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Third-party reporting indicates that the code was injected into snippets belonging to 178 organizations, including CNN, the BBC, and Zoom, on November 16.
    - lead: Search proxy and web logs for requests to domains containing .icu TLD or specifically the identified malicious hostnames and URLs.
      data_needed:
        - Proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source lists specific domains used to host exploit kits
  mitigation_plan:
    - priority: immediate
      action: Audit and review external JavaScript content loaded into public-facing web applications
      owner: Web Operations
      addresses: Supply chain compromise via Optimizely
      evidence: Attack utilized legitimate platform infrastructure to deliver malicious scripts
updates:
  - at: "2026-11-18T07:01:26Z"
    level: L1
    summary: added coverage for Optimizely website personalization platform
    sources:
      - ars-security
    source_urls:
      - https://arstechnica.com/security/2026/11/malicious-code-delivered-through-optimizely-hits-visitors-to-hundreds-of-sites/
---

## Overview

Researchers identified a wide-reaching supply chain attack affecting the Optimizely platform, where attackers injected malicious JavaScript, referred to as 'track.js', into client-hosted pages. The injected code is served directly from the legitimate cdn.optimizely.com infrastructure, signed by a valid Optimizely certificate. The attack affects at least 178 websites and includes a multi-stage payload delivery mechanism. The method of initial access, whether through compromised Optimizely systems or credential theft, remains under investigation.

## Attack Chain

1. Attackers gain unauthorized access to Optimizely platform infrastructure.
2. Malicious 'track.js' script is injected into JavaScript snippets served to Optimizely customers.
3. Legitimate customer websites load the tainted 'track.js' directly from cdn.optimizely.com.
4. Script executes in the visitor's browser, performing cryptocurrency wallet address swapping and payment card skimming.
5. Script exfiltrates stolen data (cookies, wallet addresses, screenshots) to attacker-controlled infrastructure.
6. 'boot.js' is loaded from external malicious domains (e.g., 5vobauua3ojpklx.icu) to deliver iOS exploit kits.
7. Exploit kits (Coruna/DarkSword) deploy to target devices based on the detected iOS version.

## Impact

Observed impacts include the theft of cryptocurrency funds, exfiltration of payment card data (expiry, numbers, and CVV), and theft of sensitive session cookies and screenshots. The attack also attempts to install Coruna and DarkSword exploit kits on iOS devices (versions 13-17 and 18.x respectively).

## Recommendation

- Website administrators utilizing Optimizely should immediately audit outgoing JavaScript snippets and review logs for requests to the identified malicious domains (1688360.cc, 5vobauua3ojpklx.icu, eil786npto9u5bq.icu).
- Implement strong Content Security Policy (CSP) headers to restrict script loading to known-good domains and prevent unauthorized data exfiltration to non-trusted endpoints.
- Monitor for abnormal outbound HTTPS traffic originating from user-facing web pages to unrecognized domains.
- Advise users to update iOS devices to the latest available versions to mitigate exploit kit effectiveness.
