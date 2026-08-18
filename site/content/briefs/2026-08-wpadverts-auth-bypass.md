---
title: Authorization Bypass Vulnerability in WPAdverts Classifieds Plugin
slug: 2026-08-wpadverts-auth-bypass
description: The WPAdverts - Classifieds Plugin for WordPress up to version 2.3.2 is vulnerable to an authorization bypass allowing unauthenticated attackers to exfiltrate internal configuration data via the REST API.
date: "2026-08-18T04:52:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - vulnerability
  - information-disclosure
vendors:
  - WPAdverts
products:
  - WPAdverts - Classifieds Plugin
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to retrieve internal site configuration data exposed by the classifieds-types REST endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-11801
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11801
rules:
  - title: Detect CVE-2026-11801 - Unauthorized REST API Configuration Access
    description: Detects unauthorized access attempts to the WPAdverts classifieds-types REST endpoint which may indicate exploitation of CVE-2026-11801.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch WPAdverts - Classifieds Plugin to version > 2.3.2
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable in all versions up to and including 2.3.2
    - action: Deploy webserver detection rule to monitor for endpoint reconnaissance
      owner: Detection Engineering
      due: 24h
      evidence: Unauthenticated attackers can retrieve internal site configuration data exposed by the classifieds-types REST endpoint
---

The WPAdverts - Classifieds Plugin for WordPress, versions up to and including 2.3.2, contains an authorization bypass vulnerability identified as CVE-2026-11801. This flaw stems from a failure in the plugin to properly verify user permissions before executing actions within the classifieds-types REST API endpoint. As a result, an unauthenticated attacker can query the endpoint to retrieve internal site configuration metadata. This exfiltrated information includes registered post types, labels, associated taxonomies, form scheme metadata, contact options, and custom field meta keys. Such information disclosure facilitates reconnaissance, allowing attackers to better understand the target environment's structure for subsequent exploitation or targeted attacks against specific forms and data structures.

## Impact

Successful exploitation allows unauthenticated attackers to harvest internal WordPress site configuration data. This reconnaissance data provides an attacker with deep insight into the site's data architecture, which is a critical precursor to identifying further vulnerabilities in custom forms or taxonomy-based operations.

## Recommendation

* Update the WPAdverts - Classifieds Plugin to the latest available version (beyond 2.3.2) immediately to patch the authorization logic in the classifieds-types endpoint.
* Monitor web server access logs for anomalous, high-frequency requests originating from unauthenticated sources to REST API endpoints associated with the wp-adverts plugin.
* Implement request rate limiting on the REST API for endpoints associated with the plugin to prevent automated scraping of configuration metadata.
