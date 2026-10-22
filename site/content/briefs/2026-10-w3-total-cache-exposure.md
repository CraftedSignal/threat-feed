---
brief_id: brief-2026-10-22-w3-total-cache-exposure
event_id: brief-2026-10-22-w3-total-cache-exposure
revision: 1
activity_at: "2026-10-22T15:00:35Z"
title: Boldgrid W3 Total Cache Cleartext Credential Storage (CVE-2023-5359)
slug: 2026-10-w3-total-cache-exposure
description: CVE-2023-5359 is a cleartext credential storage vulnerability in W3 Total Cache versions 2.7.5 and earlier that allows unauthenticated remote attackers to retrieve API keys and OAuth secrets via direct HTTP requests to plugin PHP files.
date: "2026-10-22T15:00:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source verified; environment validation pending
tags:
  - wordpress
  - vulnerability
  - credential-exposure
  - web-application
vendors:
  - Boldgrid
products:
  - W3 Total Cache (< 2.7.6)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: This vulnerability allows remote attackers to access sensitive credentials stored in unencrypted PHP files that are publicly accessible.
    confidence_band: high
cves:
  - id: CVE-2023-5359
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ENZOCIPHER-CVE-2023-5359
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ENZOCIPHER-CVE-2023-5359&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2023-5359 Exploitation Attempts - Unauthorized Access to W3 Total Cache Config Files
    description: Detects unauthorized HTTP GET requests to known sensitive PHP files within the W3 Total Cache plugin directory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch W3 Total Cache to version 2.7.6 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin changelog requirement
    - action: Deploy webserver detection rule for unauthorized access to plugin PHP files
      owner: Detection Engineering
      due: 48h
      evidence: Exploit PoC file list
  mitigation_plan:
    - priority: immediate
      action: Restrict access to plugin PHP files via server configuration
      owner: IT Operations
      addresses: CVE-2023-5359
      evidence: Source provided .htaccess recommendation
---

CVE-2023-5359 affects the WordPress plugin W3 Total Cache (versions ≤ 2.7.5). The plugin stores sensitive configuration and API credentials in plain text within PHP files located in the `/wp-content/plugins/w3-total-cache/` directory. Due to insufficient access control, these files are directly accessible via standard HTTP GET requests, leading to the exposure of CloudFlare API keys, client secrets, and other third-party service credentials.

## Impact
Successful exploitation allows unauthenticated remote attackers to obtain sensitive credentials. This may result in the takeover of associated services (e.g., CloudFlare DNS and CDN management), unauthorized access to external service accounts via compromised OAuth tokens, and potential manipulation of cached website content.

## Recommendation
- Update the W3 Total Cache plugin to version 2.7.6 or later immediately.
- Revoke and regenerate all API keys, OAuth tokens, and client secrets associated with the affected WordPress installation.
- Implement access restrictions in the web server configuration (e.g., .htaccess for Apache) to deny direct access to PHP files within the plugin directory, while explicitly allowing access only to required entry points like 'w3-total-cache.php'.
- Conduct an audit of logs for unauthorized HTTP GET requests directed at the `/wp-content/plugins/w3-total-cache/` path to determine if exploitation has occurred.
