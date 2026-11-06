---
brief_id: brief-2026-11-06-apache-james-webadmin
event_id: brief-2026-11-06-apache-james-webadmin
revision: 1
activity_at: "2026-11-06T17:22:59Z"
title: 'Apache James: WebAdmin REST API exposed without authentication (CVE-2026-74756)'
slug: 2026-11-apache-james-webadmin
description: A configuration vulnerability in Apache James default docker-compose files exposes the WebAdmin REST API to public access without authentication, enabling unauthorized administrative interaction.
date: "2026-11-06T17:22:59Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-based assessment complete; environment validation required to identify specific exposed deployment instances.
cpes:
  - cpe:2.3:a:apache:james:*:*:*:*:*:*:*:*
tags:
  - webserver
  - configuration-issue
  - vulnerability
vendors:
  - Apache Software Foundation
products:
  - Apache James (< 3.9.1)
cves:
  - id: CVE-2026-74756
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/549
  - https://james.apache.org/
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify exposed WebAdmin REST API endpoints accessible from the public internet
      technique_id: T1190
      data_needed:
        - Network firewall logs showing inbound connections to Apache James management ports
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Some docker-compose shipped by the project exposes by default Webadmin REST API publically without proper authentication setup.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache James to 3.9.1 or later
      owner: IT Operations
      addresses: CVE-2026-74756
      evidence: Version 3.9.1 onward sets a random credential by default on unprotected webadmin endpoints to prevent this while retain convenience.
---

Apache James versions prior to 3.9.1 contain a configuration vulnerability where the WebAdmin REST API is exposed publicly without requiring authentication when using specific provided docker-compose configurations. This allows unauthenticated users to interact with administrative API endpoints. The project has addressed this in version 3.9.1 by implementing a default random credential requirement for these endpoints to ensure security while maintaining usability.

## Impact

Successful exploitation allows unauthenticated remote actors to access the WebAdmin REST API, potentially leading to unauthorized system administration or configuration changes within the Apache James server environment.

## Recommendation

- Upgrade Apache James to version 3.9.1 or later to leverage the mandatory random default credentials.
- Audit existing docker-compose deployments to ensure WebAdmin REST API ports are not exposed to untrusted network segments.
- Apply host-based or network-level firewall rules to restrict access to the WebAdmin API ports exclusively to authorized management subnets.
