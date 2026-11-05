---
brief_id: brief-2026-11-04-ruby-on-rails-multiple-vulnerabilities
event_id: brief-2026-11-04-ruby-on-rails-multiple-vulnerabilities
revision: 3
activity_at: "2026-11-04T22:57:59Z"
revision_history:
  - revision: 2
    at: "2026-11-04T16:24:48Z"
    checksum: sha256:6521abbb029f70fef84fb13b6d499dd8299e6110ad4076e7914bd8bc789ae377
    summary: ruby on rails version 8.x < 8.1.4.1
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1452/
  - revision: 3
    at: "2026-11-04T22:57:59Z"
    checksum: sha256:9c7b8dc63fd3a2546d6f083955eb49c468c92abd5a04853b055a1db8cac029bf
    summary: new product
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - references
      - severity
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://pwn.watch/i/rails-active-storage-imagemagick-file-write-ghsa-f3w6-w445-fwh9
title: 'Ruby on Rails: Arbitrary File Read and Write via Active Storage and ImageMagick (GHSA-f3w6-w445-fwh9)'
slug: 2026-11-ruby-on-rails-multiple-vulnerabilities
description: A critical vulnerability in the Rails Active Storage component allows unauthenticated attackers to perform arbitrary file reads and writes by uploading crafted image files that exploit the ImageMagick processing suite.
date: "2026-11-04T16:19:52Z"
lastmod: "2026-11-04T22:57:23Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - rails
  - vulnerability
  - web-framework
  - application-security
  - imagemagick
  - file-upload
  - critical-vulnerability
vendors:
  - Ruby on Rails
products:
  - Ruby on Rails
  - Ruby on Rails (< 8.0.5.2)
  - Ruby on Rails (8.x < 8.1.4.1)
  - Active Storage (< 8.0.5.2)
  - Active Storage (< 8.1.4.1)
  - Active Storage (>= 8.1, < 8.1.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Rails application that processes attachments with ImageMagick may allow an unauthenticated attacker to write arbitrary files on the server.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4317
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1452/
  - https://github.com/advisories/GHSA-f3w6-w445-fwh9
  - https://www.darkreading.com/application-security/critical-rails-bug-derail-vulnerable-servers
  - https://pwn.watch/i/rails-active-storage-imagemagick-file-write-ghsa-f3w6-w445-fwh9
  - https://github.com/rails/rails/security/advisories/GHSA-f3w6-w445-fwh9
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Inventory all internet-facing Ruby on Rails applications.
      owner: IT Operations
      due: 24h
      evidence: BSI notice identifies multiple vulnerabilities in Ruby on Rails
    - action: Patch Rails Active Storage to 8.0.5.2 or 8.1.4.1.
      owner: IT Operations
      due: 24h
      evidence: GitHub advisory (GHSA-f3w6-w445-fwh9) patches.
    - action: Rotate all application secrets and credentials if Disk service was used.
      owner: IT Operations
      due: 48h
      evidence: GitHub advisory (GHSA-f3w6-w445-fwh9) mitigation requirements.
  hunt_leads:
    - lead: Monitor for suspicious web requests targeting Rails applications (e.g., unexpected characters in input parameters, large payload bursts)
      data_needed:
        - Web server access logs
        - WAF request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerabilities can result in RCE, DoS, information disclosure, and XSS
    - lead: Hunt for anomalous image uploads to application endpoints followed by reads of sensitive configuration files.
      data_needed:
        - Web server access logs
        - Application error logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers target file upload components and attempt to read sensitive application configuration files.
  mitigation_plan:
    - priority: immediate
      action: Subscribe to official Ruby on Rails security announcements and prepare for emergency patching once specific versions are announced.
      owner: IT Operations
      addresses: Multiple undisclosed vulnerabilities
      evidence: BSI advisory indicates multiple security flaws
    - priority: immediate
      action: Apply ImageMagick system policy restrictions provided in GHSA-f3w6-w445-fwh9.
      owner: IT Operations
      addresses: ImageMagick decoder selection flaw
      evidence: GitHub advisory (GHSA-f3w6-w445-fwh9) mitigation.
updates:
  - at: "2026-11-04T16:23:09Z"
    level: L2
    summary: ruby on rails version 8.x < 8.1.4.1
    sources:
      - anssi
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1452/
  - at: "2026-11-04T22:57:20Z"
    level: L3
    summary: severity → critical
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/application-security/critical-rails-bug-derail-vulnerable-servers
  - at: "2026-11-04T22:57:23Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/rails-active-storage-imagemagick-file-write-ghsa-f3w6-w445-fwh9
---

A critical vulnerability (GHSA-f3w6-w445-fwh9) exists in the Ruby on Rails Active Storage component when configured to use ImageMagick for image processing. The flaw stems from ImageMagick selecting image decoders based on file content rather than file extensions. Unauthenticated attackers can exploit this by uploading crafted image files, enabling arbitrary file writes to the server and arbitrary file reads of any files accessible to the application process. Successful exploitation may lead to the exposure of sensitive secrets, such as `secret_key_base`, database credentials, and third-party tokens, facilitating lateral movement or remote code execution.

## Impact
Impact includes unauthorized read/write access to the server filesystem, theft of application secrets, and potential full system compromise. If attachments are stored with the Disk service, secrets such as `config/credentials.yml.enc` and external system credentials are at high risk of exfiltration.

## Recommendation
- Upgrade Rails Active Storage to version 8.0.5.2, 8.1.4.1, or later.
- If using the Disk service, rotate all application secrets immediately, including the master key, storage credentials, database passwords, and third-party API tokens, as they must be assumed compromised if previously stored.
- Apply the recommended ImageMagick system policy rules provided in the GitHub advisory to restrict dangerous coders.
- Inventory all Rails applications using Active Storage with ImageMagick to identify exposure.
