---
brief_id: brief-2026-10-27-grav-debugger-auth-bypass
event_id: brief-2026-10-27-grav-debugger-auth-bypass
revision: 1
activity_at: "2026-10-27T15:51:13Z"
title: 'Grav: Authorization bypass in Debugger component (CVE-2026-117604)'
slug: 2026-10-grav-debugger-auth-bypass
description: An authorization bypass vulnerability in the Grav CMS Debugger component allows unauthenticated remote attackers to access sensitive profiler data when the application is deployed behind a reverse proxy.
date: "2026-10-27T15:51:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:getgrav:grav:1.7.53.3:*:*:*:*:*:*:*
  - cpe:2.3:a:getgrav:grav:1.7.53.4:*:*:*:*:*:*:*
  - cpe:2.3:a:getgrav:grav:1.7.53.5:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Grav (1.7.53.3 to 1.7.53.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grav from 1.7.53.3 before 1.7.53.6 contains an authorization bypass... that allows unauthenticated visitors to read /__clockwork/ profiler data
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: remote requests appear as loopback, letting attackers read stored records including administrator plaintext passwords and configuration credentials
    confidence_band: high
cves:
  - id: CVE-2026-117604
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117604
rules:
  - title: Detect CVE-2026-117604 Exploitation Attempt - Access to Clockwork Profiler
    description: Detects unauthorized access attempts to the Clockwork profiler endpoint, which is a indicator of exploitation for CVE-2026-117604
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Grav to version 1.7.53.6
      owner: IT Operations
      due: 24h
      evidence: Upgrade Grav to 1.7.53.6 or later
  hunt_leads:
    - lead: Identify GET requests to /__clockwork/ from external IP addresses
      technique_id: T1552.001
      data_needed:
        - Web server logs (cs-uri-stem, c-ip)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated visitors can read /__clockwork/ profiler data
  mitigation_plan:
    - priority: immediate
      action: Restrict /__clockwork/ path access at the reverse proxy level
      owner: IT Operations
      addresses: CVE-2026-117604
      evidence: restricting access to the /__clockwork/ path via reverse proxy configuration
---

Grav versions 1.7.53.3 through 1.7.53.5 contain an authorization bypass vulnerability within the Debugger::isDebuggerRequestAuthorized() method. The vulnerability arises from an insecure fallback mechanism that trusts the REMOTE_ADDR variable. When the application is deployed behind a reverse proxy, requests may be incorrectly identified as originating from the local loopback, bypassing access controls for the /__clockwork/ endpoint.

## Impact

Unauthenticated remote attackers can access the /__clockwork/ profiler data. This exposure may include sensitive configuration credentials and administrator plaintext passwords stored within the profiler records.

## Recommendation

* Upgrade Grav to version 1.7.53.6 or later immediately.
* If an immediate upgrade is not possible, disable the Debugger component or restrict access to the /__clockwork/ path via reverse proxy configuration (e.g., Nginx or Apache) to ensure only authorized administrative IPs are permitted.
* Audit logs for suspicious GET requests to the /__clockwork/ directory from external IP addresses to identify potential prior exploitation.
