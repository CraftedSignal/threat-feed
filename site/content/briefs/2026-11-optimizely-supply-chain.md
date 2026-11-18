---
brief_id: brief-2026-11-17-optimizely-supply-chain
event_id: brief-2026-11-17-optimizely-supply-chain
revision: 3
activity_at: "2026-11-18T17:15:07Z"
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
  - revision: 3
    at: "2026-11-18T17:15:07Z"
    checksum: sha256:92b24461f57c2bdac3854073b356835b98ec3be5d63463f9928af5dad4af0c7c
    summary: added coverage for Optimizely Web Experimentation
    changed_fields:
      - action_plan
      - affected_products
      - content
      - iocs
      - lastmod
      - references
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://therecord.media/optimizely-malicious-code-customer-sites
title: 'Optimizely: Malicious JavaScript injection via Web Experimentation platform'
slug: 2026-11-optimizely-supply-chain
description: Threat actors exploited a vulnerability in the Optimizely Web Experimentation platform to inject malicious JavaScript into customer-managed websites for payment skimming, credential theft, and delivery of exploit kits.
date: "2026-11-17T20:54:45Z"
lastmod: "2026-11-18T17:14:47Z"
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
  - web-skimming
  - exploit-kit
vendors:
  - Optimizely
products:
  - Optimizely Web Experimentation
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
  - https://therecord.media/optimizely-malicious-code-customer-sites
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
    - priority: immediate
      action: Audit Optimizely 'Project JavaScript' configurations for unauthorized code.
      evidence: The attacker's loader went into Project JavaScript, the field where a customer adds custom code to Optimizely.
updates:
  - at: "2026-11-18T07:01:26Z"
    level: L1
    summary: added coverage for Optimizely website personalization platform
    sources:
      - ars-security
    source_urls:
      - https://arstechnica.com/security/2026/11/malicious-code-delivered-through-optimizely-hits-visitors-to-hundreds-of-sites/
  - at: "2026-11-18T17:14:47Z"
    level: L1
    summary: added coverage for Optimizely Web Experimentation
    sources:
      - therecord
    source_urls:
      - https://therecord.media/optimizely-malicious-code-customer-sites
---

## Overview
Optimizely confirmed that a vulnerability in its Web Experimentation platform allowed threat actors to inject malicious JavaScript code into customer-managed websites. The injected code was hosted in 'Project JavaScript', a feature where customers add custom code to Optimizely for website personalization. Optimizely stated that the vulnerable path has been blocked, the injected code was removed, and affected customers have been contacted.

## Attack Chain
1. A vulnerability in the Optimizely Web Experimentation platform enabled the injection of malicious JavaScript into customer sites.
2. Malicious code was executed in the browsers of users visiting the impacted websites.
3. The script performed multi-purpose activities, including swapping cryptocurrency wallet addresses, skimming payment card data from forms, and stealing cookies and screenshots.
4. iOS users were redirected to infrastructure delivering the Coruna and DarkSword exploit kits, which utilize WebKit and kernel vulnerabilities.

## Impact
Researchers identified malicious JavaScript on 178 widely visited websites, including finance, banking, technology, news, airline, and retail sectors. Documented impact includes theft of cryptocurrency, exfiltration of payment card data, and potential compromise of iOS devices. The full scale of stolen credit card numbers, cookies, and screenshots remains unknown.

## Recommendation
Optimizely customers are advised to audit their Optimizely 'Project JavaScript' configurations to ensure no unauthorized code persists. Organizations that processed payments via forms during the incident period should initiate forensic investigations to assess potential exposure of payment card data and satisfy compliance requirements.
