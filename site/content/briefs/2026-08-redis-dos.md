---
title: Redis Vulnerability Enables Denial of Service and Information Disclosure
slug: 2026-08-redis-dos
description: A vulnerability in Redis allows an attacker located in an adjacent network to trigger a Denial of Service condition and perform unauthorized information disclosure.
date: "2026-08-11T11:35:23Z"
lastmod: "2026-08-11T11:39:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Redis
products:
  - Redis
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein Angreifer aus einem angrenzenden Netzwerk kann eine Schwachstelle in Redis ausnutzen, um einen Denial of Service Angriff durchzuführen und Informationen offenzulegen.
    confidence_band: high
cves:
  - id: CVE-2026-72568
    cvss: 7.1
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2745
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72568
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict Redis network access via host-based firewalls or network segmentation.
      owner: IT Operations
      due: 48h
      evidence: Source identifies threat vector as an attacker in an adjacent network.
  mitigation_plan:
    - priority: immediate
      action: Monitor Redis vendor channels for patches.
      owner: IT Operations
      addresses: Redis
      evidence: Security advisory reports vulnerability requiring remediation.
updates:
  - at: "2026-08-11T11:39:43Z"
    level: L2
    summary: added CVE-2026-72568
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72568
---

The German Federal Office for Information Security (BSI) has reported a vulnerability in Redis that impacts availability and data confidentiality. The vulnerability allows an attacker positioned within an adjacent network to execute a Denial of Service (DoS) attack against the Redis service, potentially causing service instability or total unavailability. Additionally, the flaw enables the unauthorized disclosure of information held within the Redis instance. As of the report date, specific patch availability or version numbers were not explicitly detailed, requiring administrators to monitor official Redis project channels for security updates. This vulnerability is critical for environments where Redis instances are exposed to adjacent networks without strict segmentation or access control.

## Impact

Successful exploitation of this vulnerability results in service disruption via Denial of Service and the exposure of sensitive data managed by Redis. This impact is significant for applications relying on Redis for session management, caching, or message brokering, as unauthorized parties may gain access to transient data or force system downtime, affecting business continuity and data integrity.

## Recommendation

* Review network architecture to ensure Redis instances are not accessible from untrusted or adjacent networks.
* Implement host-based firewalls or access control lists (ACLs) to restrict connections to Redis ports (default 6379) to known, authorized management or application hosts.
* Monitor Redis logs for anomalous connection patterns or unexpected command activity.
* Review official Redis security advisories for patches and apply updates as soon as they become available.
