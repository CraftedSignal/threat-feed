---
brief_id: brief-2026-11-17-optimizely-supply-chain
event_id: brief-2026-11-17-optimizely-supply-chain
revision: 6
activity_at: "2026-11-24T23:25:33Z"
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
  - revision: 4
    at: "2026-11-19T16:34:37Z"
    checksum: sha256:738a017353bf50268af606546d20c3b82ee1ba4d0f78317310bb754bd472f85b
    summary: poc_available
    changed_fields:
      - affected_products
      - content
      - has_poc
      - iocs
      - lastmod
      - references
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/
  - revision: 5
    at: "2026-11-23T19:15:02Z"
    checksum: sha256:a492b6d9859a57df5327ac36fdc879b27f1257e6e8fdc0cc10ba345890c4aa44
    summary: added CVE-2026-132224
    changed_fields:
      - cpes
      - cve_verification
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-132224
  - revision: 6
    at: "2026-11-24T23:25:33Z"
    checksum: sha256:98c9a1cc7adb2e6abaee81513f70d354c0a5cb89729d7fe33e63a48ed2a9c1fa
    summary: KEV CVE-2026-132224
    changed_fields:
      - cves
      - iocs
      - lastmod
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: 'Optimizely: Malicious JavaScript injection via supply chain attack'
slug: 2026-11-optimizely-supply-chain
description: An unauthorized party exploited a vulnerability in the Optimizely Experimentation platform to inject malicious JavaScript into 178 customer websites, enabling the distribution of a multi-purpose malware kit to visitors.
date: "2026-11-17T20:54:45Z"
lastmod: "2026-11-24T23:24:59Z"
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
cpes:
  - cpe:2.3:a:optimizely:web_experimentation:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - supply-chain
  - web-application
  - js-injection
  - javascript-injection
  - malware
  - web
  - web-skimming
  - exploit-kit
  - web-exploitation
  - javascript
vendors:
  - Optimizely
products:
  - Optimizely Experimentation
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
cve_verification:
  CVE-2026-132224:
    status: verified
    source: nvd
    checked_at: 2026-11-23T19:13:11.401586726Z
cves:
  - id: CVE-2026-132224
    cvss: 8.7
    epss: 0.00426
    kev: true
    kev_status: "true"
references:
  - https://www.sophos.com/en-us/blog/hijacked-optimizely-snippets-served-malicious-code
  - https://arstechnica.com/security/2026/11/malicious-code-delivered-through-optimizely-hits-visitors-to-hundreds-of-sites/
  - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
  - https://therecord.media/optimizely-malicious-code-customer-sites
  - https://www.sonatype.com/blog/optimizely-attack-shows-why-supply-chain-ownership-matters
  - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
  - https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/
  - https://pages.optimizely.com/rs/947-RKE-048/images/Security%20Incident%20Report%20-%20Optimizely%20Web%20Experimentation%20-%20Nov%2017%202026.pdf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-132224
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
  - at: "2026-11-19T16:32:42Z"
    level: L2
    summary: poc_available
    sources:
      - krebs-breaches
    source_urls:
      - https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/
  - at: "2026-11-23T19:13:11Z"
    level: L2
    summary: added CVE-2026-132224
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-132224
  - at: "2026-11-24T23:24:59Z"
    level: L3
    summary: KEV CVE-2026-132224
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview
On November 16, 2026, an unauthorized party exploited a vulnerability in the Optimizely Experimentation platform to inject malicious JavaScript into client projects. This supply chain compromise resulted in 178 web destinations inadvertently serving malicious code to visitors. Report URI researcher Scott Helme noted the malicious payload was rebuilt 26 times on November 16, delivering a multi-purpose malware kit capable of stealing payment card data, cookies, screenshots, and swapping cryptocurrency payment addresses. The affected websites also served exploit code targeting known vulnerabilities in older Apple iPhone and iPad devices. 

## Attack Chain
1. An unauthorized party exploited a vulnerability in Optimizely Experimentation to add malicious JavaScript to customer projects.
2. Impacted websites served the malicious JavaScript to visitors upon page load without requiring user interaction.
3. The malicious script executed in the browsers of visitors, delivering a multi-purpose malware kit or mobile-specific exploits.

## Impact
At least 178 organizations were affected. Reported impact included the theft of approximately $7,500 in virtual currency and an unknown number of payment card records. 

## Recommendation
Optimizely stated they have fully remediated the vulnerability, including blocking the vulnerable path, deploying a fix, removing injected code, ending active sessions, revoking tokens, and resetting access for affected user accounts. Additional protections were implemented to prevent malicious code delivery in Cloudflare. Websites utilizing third-party JavaScript are encouraged to implement Content Security Policies (CSP) to restrict allowed domains and mitigate the risk of third-party supply chain compromises.
