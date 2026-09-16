---
title: Authorization Bypass in PatrowlManager API
slug: 2026-09-patrowlmanager-auth-bypass
description: PatrowlManager versions up to 1.8.4 contain an authorization bypass vulnerability in events and alerts API endpoints, allowing authenticated attackers to modify or delete data across different user contexts.
date: "2026-09-16T21:54:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:patrowl:patrowlmanager:*:*:*:*:*:*:*:*
vendors:
  - Patrowl
products:
  - PatrowlManager (<= 1.8.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated attackers can read platform event history, delete arbitrary events, and modify alerts belonging to other users.
    confidence_band: high
cves:
  - id: CVE-2026-92753
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92753
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade PatrowlManager to version > 1.8.4 once a patch is released.
      owner: IT Operations
      due: 72h
      evidence: Source confirms vulnerable version range is 1.8.4 and below.
  hunt_leads:
    - lead: Anomalous API request patterns to /events or /alerts endpoints from low-privilege users
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary access to events and alerts API endpoints.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to PatrowlManager management interface to known secure network segments.
      owner: IT Operations
      addresses: CVE-2026-92753
      evidence: Authorization bypass allows any authenticated attacker access to restricted API functions.
---

PatrowlManager versions through 1.8.4 are susceptible to an authorization bypass vulnerability due to a failure to enforce ownership filtering within the application's events and alerts API endpoints. This security flaw allows any authenticated user to interact with data outside of their assigned scope. By manipulating requests to specific API routes, an attacker can read sensitive platform event history, delete events, or modify alerts belonging to other users or departments. Because the vulnerability exists at the API layer, it requires an existing authenticated session but does not require administrative privileges. This poses a significant risk to the integrity and confidentiality of security operations data within organizations utilizing PatrowlManager for vulnerability and threat management.

## Impact

Successful exploitation of this vulnerability results in unauthorized access to sensitive security event logs and alert management functions. Impacted organizations face potential data loss through the deletion of security alerts and the exposure of proprietary platform usage patterns. Given the context of PatrowlManager as a security orchestration and vulnerability management tool, unauthorized modification of alerts can be leveraged to suppress incident visibility, potentially facilitating a wider, undetected security compromise.

## Recommendation

Prioritize the immediate upgrade of all PatrowlManager instances to a patched version beyond 1.8.4 as soon as the vendor makes a fix available. Until patching is completed, implement strict access controls on the network to limit the exposure of the application's management interface to trusted internal networks only. Monitor web server logs for high-frequency or anomalous API requests targeting the /events or /alerts endpoints from non-administrative service accounts.
