---
brief_id: brief-2026-10-iofog-auth-bypass
event_id: brief-2026-10-iofog-auth-bypass
revision: 2
activity_at: "2026-10-20T14:44:14Z"
revision_history:
  - revision: 2
    at: "2026-10-20T14:44:14Z"
    checksum: sha256:cb36f5709be66d6f4c55acf698de7c8b43eb8684befaef4ff0ab44796a69fbe6
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-113620&utm_source=rss&utm_medium=rss
title: 'Eclipse ioFog Controller: WebSocket Authentication Bypass (CVE-2026-113620)'
slug: 2026-10-iofog-auth-bypass
description: Eclipse ioFog Controller versions 3.8.0 through 3.9.1 contain an authentication bypass vulnerability in operator WebSocket endpoints, allowing attackers to access exec and log sessions using self-minted bearer tokens.
date: "2026-10-20T14:17:38Z"
lastmod: "2026-10-20T14:43:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:eclipse:iofog_controller:3.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:iofog_controller:3.9.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-113620&utm_source=rss&utm_medium=rss
tags:
  - authentication-bypass
  - web-application-vulnerability
  - cloud-edge
vendors:
  - Eclipse
products:
  - ioFog Controller (3.8.0 through 3.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The operator WebSocket upgrades on the exec and log routes do not verify the bearer JWT.
    confidence_band: high
cves:
  - id: CVE-2026-113620
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113620
  - https://sploitus.com/exploit?id=CVE-2026-113620&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Eclipse ioFog Controller to a version patched against CVE-2026-113620
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-113620 affects versions 3.8.0 through 3.9.1
  hunt_leads:
    - lead: Identify WebSocket upgrade requests to log or exec routes in web server logs
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs on WebSocket upgrades on the exec and log routes
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-113620
      owner: IT Operations
      addresses: CVE-2026-113620
      evidence: NVD advisory
updates:
  - at: "2026-10-20T14:43:04Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-113620&utm_source=rss&utm_medium=rss
---

Eclipse ioFog Controller versions 3.8.0 through 3.9.1 are affected by an authentication bypass vulnerability (CVE-2026-113620) within the operator WebSocket implementation. Specifically, the exec and log routes fail to perform proper validation of the provided bearer JSON Web Token (JWT). The application decodes the token and incorrectly utilizes the groups or roles defined within the payload as RBAC subjects. An attacker can craft a self-minted token containing administrative groups to bypass authorization checks, as the system does not require an associated account or RoleBinding. This flaw allows unauthorized actors to initiate exec or log sessions for specific microservices or fog instances, provided the attacker has obtained the target's UUID. HTTP routes and Agent WebSockets correctly verify tokens and remain unaffected.

## Impact

Successful exploitation allows unauthorized administrative access to container exec and log streams. This could lead to sensitive information disclosure via logs or full command execution on managed microservices and fog instances, potentially allowing an attacker to move laterally or exfiltrate data within the fog edge computing environment.

## Recommendation

* Patch the Eclipse ioFog Controller by upgrading to a version released after 3.9.1 that addresses CVE-2026-113620.
* Audit access logs for WebSockets requests to the ioFog Controller that originate from unauthorized internal segments or external sources.
* Monitor for unexpected exec or log session initiation for critical microservices or fog instances, especially those appearing with administrative role claims that do not correspond to known service identities.
