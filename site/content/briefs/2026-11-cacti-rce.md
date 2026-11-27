---
brief_id: brief-2026-11-26-cacti-rce
event_id: brief-2026-11-26-cacti-rce
revision: 2
activity_at: "2026-11-27T14:56:12Z"
revision_history:
  - revision: 2
    at: "2026-11-27T14:56:12Z"
    checksum: sha256:c0f958b26b3fdbeba153233ee368640c97e496610ab2cc0f9e3daf258d4694d1
    summary: severity → critical
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - severity
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4845
title: 'Cacti: Unauthenticated remote code execution (4HTTP2ROOT)'
slug: 2026-11-cacti-rce
description: Cacti Core 1.2.31 contains an unauthenticated remote code execution vulnerability that allows attackers to execute arbitrary shell commands via database query manipulation.
date: "2026-11-26T20:51:07Z"
lastmod: "2026-11-27T14:53:38Z"
type: advisory
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Content verified against provided watchTowr brief.
vendors:
  - Cacti
products:
  - Cacti (unpatched)
  - Cacti Core
product_versions:
  - product: Cacti Core
    range: 1.2.31
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attacker starts as an anonymous guest, writes an unvalidated value into a per user display setting, and that value is later inserted into a database query that the server treats as more than one command.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: One of those extra commands changes a poller setting to a shell command, which a separate guest reachable page then executes.
    confidence_band: high
references:
  - https://watchtowr.com/intelligence/4http2root-cacti-zero-day-faq/
  - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4845
rules:
  - title: Detect Cacti 4HTTP2ROOT Exploitation Attempt
    description: Detects potential exploitation of 4HTTP2ROOT by monitoring Cacti logs for application-level warning messages regarding non-numeric values being written to display settings.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Disable the guest account in Cacti administration settings.
      owner: IT Operations
      due: 24h
      evidence: Disable the guest account within Cacti's user administration settings to remove the chain's entry point.
    - action: Restrict Cacti web interface access to trusted internal networks.
      owner: IT Operations
      due: 24h
      evidence: Restrict network access to the Cacti web interface to trusted internal networks only.
    - action: Inventory all Cacti installations and verify they are not exposed to the internet.
      owner: IT Operations
      due: 24h
      evidence: Cacti vulnerability allows unauthenticated remote code execution.
  hunt_leads:
    - lead: Review Cacti poller configuration for unexpected command entries.
      technique_id: T1059
      data_needed:
        - Cacti configuration database
        - Poller logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unexpected commands configured in poller settings, or new files created by the poller process, are further signs that the chain has run.
    - lead: Hunt for anomalous SQL query syntax or common SQL injection payloads in web server logs targeting Cacti endpoints.
      technique_id: T1190
      data_needed:
        - web server access logs (cs-uri-query, cs-method)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw allows remote SQL injection leading to code execution.
  mitigation_plan:
    - priority: immediate
      action: Restrict Cacti access to authorized internal users via VPN or network segmentation.
      owner: IT Operations
      addresses: Cacti unpatched vulnerability
      evidence: The vulnerability is remote and unauthenticated.
updates:
  - at: "2026-11-27T14:53:38Z"
    level: L3
    summary: severity → critical
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4845
---

## Overview
Cacti Core version 1.2.31 is vulnerable to an unauthenticated remote code execution (RCE) flaw, dubbed 4HTTP2ROOT. The vulnerability allows an unauthenticated guest user to execute arbitrary operating system commands on the Cacti server by injecting malicious values into per-user display settings. These settings are subsequently inserted into a database query, enabling command injection that modifies the poller configuration to include shell commands. The Cacti web server and poller process then execute these commands.

## Attack Chain
1. An attacker initiates an unauthenticated guest session on the Cacti server.
2. The attacker writes an unvalidated value into a user display setting.
3. The application incorporates this value into a database query that is treated as multiple commands.
4. The database query manipulation allows for the modification of the poller configuration.
5. The poller configuration is updated to include a malicious shell command.
6. A separate, guest-accessible page triggers the execution of the poller setting, running the shell command on the server.

## Impact
Successful exploitation results in command execution on the Cacti server with the privileges of the web user or poller process. As Cacti centralizes credentials and configuration for network infrastructure, this access may facilitate further lateral movement within the environment.

## Recommendation
1. Disable the guest account in Cacti user administration settings immediately to remove the primary entry point.
2. Restrict access to the Cacti web interface to trusted internal networks only.
3. Monitor application logs for warning messages regarding non-numeric values in display settings.
4. Audit poller configuration settings for unexpected entries that do not align with authorized monitoring configurations.
5. Monitor for unexpected file creation by the poller process.
6. Prepare to apply a patch as soon as one is provided by the vendor.
