---
brief_id: brief-2026-10-23-php-session-injection
event_id: brief-2026-10-23-php-session-injection
revision: 3
activity_at: "2026-11-23T22:43:30Z"
revision_history:
  - revision: 2
    at: "2026-10-26T16:14:36Z"
    checksum: sha256:c4e7133067501dc79cc237be71719bc4aeb21b4cc433db1f6ceb319904e2bbe6
    summary: new product
    changed_fields:
      - affected_products
      - affected_vendors
      - lastmod
      - references
      - updates
    source_urls:
      - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
  - revision: 3
    at: "2026-11-23T22:43:30Z"
    checksum: sha256:5f7fc0a1772e4b9601891f51096bed3cc73e3272518608301534ad720e75e01b
    summary: added coverage for PHP (< 8.2.36, 8.3.* < 8.3.37, 8.4.* < 8.4.28, 8.5.* < 8.5.13)
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - qa_status
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/web/php_serialized_object_in_post_body.yml
title: 'PHP: Remote code execution via session serializer mismatch (CVE-2026-115560)'
slug: 2026-10-php-session-injection
description: A session serializer mismatch in PHP allows remote attackers to inject serialized objects via HTTP POST bodies, potentially leading to remote code execution if a suitable gadget chain exists in the target application.
date: "2026-10-23T17:43:39Z"
lastmod: "2026-11-23T22:42:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Content verified against PHP advisory and CVE data
cpes:
  - cpe:2.3:a:php_group:php:*:*:*:*:*:*:*:*
tags:
  - cve-2026-115560
  - web-vulnerability
  - remote-code-execution
vendors:
  - PHP
  - PHP Group
products:
  - PHP
  - PHP (< 8.2.36, 8.3.* < 8.3.37, 8.4.* < 8.4.28, 8.5.* < 8.5.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker able to submit a multipart upload can inject objects, which may lead to code execution when the reading application contains a suitable gadget chain.
    confidence_band: high
cves:
  - id: CVE-2026-115560
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=21ECC387-5A3C-5E76-A26E-F5872215776E
  - https://sploitus.com/exploit?id=21ECC387-5A3C-5E76-A26E-F5872215776E&utm_source=rss&utm_medium=rss
  - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
  - https://cveawg.mitre.org/api/cve/CVE-2026-115560
  - https://www.php.net/ChangeLog-8.php#8.3.37
  - https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx
  - https://github.com/splunk/security_content/blob/main/detections/web/php_serialized_object_in_post_body.yml
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected PHP instances to patched versions (8.2.36, 8.3.37, 8.4.28, or 8.5.13)
      owner: IT Operations
      due: 48h
      evidence: PHP advisory CVE-2026-115560
  hunt_leads:
    - lead: Hunt for serialized PHP object markers ('|O:[0-9]+:') in HTTP POST request bodies.
      technique_id: T1190
      data_needed:
        - Zeek HTTP POST body logs
        - Web application firewall request body captures
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: This analytic finds a PHP serialized object marker in an HTTP POST body. Such input can reach unsafe deserialization paths.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PHP version to a patched release.
      owner: IT Operations
      addresses: CVE-2026-115560
      evidence: PHP security advisory GHSA-658j-r8rw-q6mx
updates:
  - at: "2026-10-26T16:13:32Z"
    level: L1
    summary: new product
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
  - at: "2026-11-23T22:42:16Z"
    level: L2
    summary: added coverage for PHP (< 8.2.36, 8.3.* < 8.3.37, 8.4.* < 8.4.28, 8.5.* < 8.5.13)
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/web/php_serialized_object_in_post_body.yml
---

## Overview
PHP is vulnerable to a remote code execution vulnerability (CVE-2026-115560) arising from a mismatch between session serializers. When session upload progress is enabled, an attacker can store data in a session key using the php_binary or php_serialize handlers. If a subsequent request reads the same session key using the standard php serializer, the content is passed to the unserializer. This process allows remote attackers who can trigger a multipart upload to perform object injection, which can lead to code execution when applications possess compatible gadget chains.

## Impact
Successful exploitation can lead to remote code execution, session corruption, or denial of service on affected PHP web servers.

## Recommendation
Upgrade PHP to the following versions or later: 8.2.36, 8.3.37, 8.4.28, or 8.5.13. In addition to patching, deploy telemetry to monitor for serialized object markers in HTTP POST bodies, which may indicate exploitation attempts. Inspect application session handling configurations to ensure consistent session serializers are used across all endpoints sharing a session store.
