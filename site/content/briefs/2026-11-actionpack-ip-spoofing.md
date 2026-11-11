---
brief_id: brief-2026-11-11-actionpack-ip-spoofing
event_id: brief-2026-11-11-actionpack-ip-spoofing
revision: 1
activity_at: "2026-11-11T02:05:16Z"
title: 'Action Pack: IP spoofing in ActionDispatch::RemoteIp (CVE-2026-126083)'
slug: 2026-11-actionpack-ip-spoofing
description: An unauthenticated attacker can spoof their remote IP address in Rails 8.1.0-8.1.4 by providing a malicious Forwarded header, potentially bypassing IP-based access controls and rate limiting.
date: "2026-11-11T02:05:16Z"
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
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:rubyonrails:actionpack:8.1.0:*:*:*:*:*:*:*
vendors:
  - Ruby on Rails
products:
  - actionpack (>= 8.1.0, < 8.1.4.1)
cves:
  - id: CVE-2026-126083
    cvss: 7.4
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-2gff-2mmg-m73p
  - https://github.com/rails/rails/commit/2d084af8444a7b6b868c7cbb256172007871e78d
  - https://github.com/rails/rails/commit/2a01a5ac521184419d9a92fa2c25e102e68cd227
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade actionpack to version 8.1.4.1 or later on all Rails applications
      owner: IT Operations
      due: 24h
      evidence: Fixed releases are available to mitigate CVE-2026-126083
  hunt_leads:
    - lead: Identify applications utilizing Rack 3 and Rails 8.1.x that are exposed to client-supplied Forwarded headers
      technique_id: T1592
      data_needed:
        - Proxy configuration logs
        - Application dependency inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability requires specific proxy configuration and Rails version 8.1.0-8.1.4
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy to scrub incoming Forwarded headers
      owner: IT Operations
      addresses: CVE-2026-126083
      evidence: Configuring reverse proxies to remove or overwrite any client-supplied Forwarded header is a recommended mitigation
---

A vulnerability in ActionDispatch::RemoteIp (CVE-2026-126083) allows unauthenticated attackers to bypass IP-based security controls by spoofing the client IP address. The vulnerability arises because Rails 8.1.0 and later, when running on Rack 3, defaults to reading the RFC 7239 'Forwarded' header. If a reverse proxy passes a client-supplied 'Forwarded' header while simultaneously appending the actual client address to the 'X-Forwarded-For' header, the application incorrectly trusts the 'Forwarded' header, allowing an attacker to choose their perceived 'remote_ip'.

## Impact
Successful exploitation may allow attackers to bypass IP-based access control lists (ACLs) and rate limits, and leads to incorrect client identification in application logs.

## Recommendation
- Upgrade to Action Pack 8.1.4.1 or later immediately.
- If upgrading is not immediately possible, configure reverse proxies to explicitly remove or overwrite the 'Forwarded' header before the request reaches the Rails application.
- Alternatively, set 'Rack::Request.forwarded_priority = [:x_forwarded]' in an initializer to force Rack to ignore the 'Forwarded' header.
- Audit logs for instances of 'ActionDispatch::RemoteIp::IpSpoofAttackError' following the deployment of the patch, as these may indicate blocked spoofing attempts.
