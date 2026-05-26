---
title: Mattermost Uncontrolled Resource Consumption Vulnerability (CVE-2026-5308)
slug: 2026-05-mattermost-dos
description: Mattermost versions 11.6.x <= 11.6.0, 11.5.x <= 11.5.3, 11.4.x <= 11.4.4, 10.11.x <= 10.11.14 fail to enforce request body size limits on plugin HTTP endpoints, allowing an attacker to cause a denial of service via crafted oversized HTTP requests.
date: "2026-05-26T13:30:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - cve
  - webserver
vendors:
  - Mattermost Inc.
products:
  - Mattermost Server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5308
  - https://mattermost.com/security-updates
rules:
  - title: Detect CVE-2026-5308 Exploitation Attempt via Large HTTP Request
    description: Detects CVE-2026-5308 exploitation attempts by monitoring for unusually large HTTP requests to Mattermost plugin endpoints.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-5308 Exploitation Attempt via HTTP Request Size
    description: Detects CVE-2026-5308 exploitation attempt by detecting excessive HTTP request size.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

A denial-of-service vulnerability, identified as CVE-2026-5308, affects Mattermost servers. Specifically, versions 11.6.x up to and including 11.6.0, 11.5.x up to and including 11.5.3, 11.4.x up to and including 11.4.4, and 10.11.x up to and including 10.11.14, do not properly enforce request body size limits on plugin HTTP endpoints. This flaw allows a remote, unauthenticated attacker to potentially exhaust server resources by sending specially crafted, oversized HTTP requests to plugin endpoints, leading to service disruption. This vulnerability is tracked under Mattermost Advisory ID MMSA-2026-00646 and has a CVSS v3.1 base score of 7.5.

## Attack Chain

1. The attacker identifies a vulnerable Mattermost server running a susceptible version.
2. The attacker identifies plugin HTTP endpoints that lack proper request body size limit enforcement.
3. The attacker crafts an oversized HTTP request targeted at one of the vulnerable plugin endpoints.
4. The malicious HTTP request is sent to the Mattermost server.
5. The Mattermost server processes the request, allocating resources without proper size validation.
6. Repeated or concurrent oversized requests exhaust server resources such as memory and CPU.
7. Legitimate user requests are delayed or fail due to resource exhaustion.
8. The Mattermost service becomes unavailable, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2026-5308 can result in a complete denial of service, preventing legitimate users from accessing the Mattermost platform. The impact is significant for organizations relying on Mattermost for communication and collaboration, potentially disrupting business operations. The severity is further underscored by the CVSS v3.1 base score of 7.5, highlighting the potential for widespread impact.

## Recommendation

- Upgrade to a patched version of Mattermost Server that addresses CVE-2026-5308.
- Implement the Sigma rule "Detect CVE-2026-5308 Exploitation Attempt via Large HTTP Request" to identify potential exploitation attempts.
- Monitor web server logs for unusually large HTTP requests targeting plugin endpoints, as this could indicate an attempted denial-of-service attack.
- Configure web application firewalls (WAFs) to enforce request body size limits, mitigating the vulnerability at the network level.
