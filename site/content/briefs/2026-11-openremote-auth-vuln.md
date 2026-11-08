---
brief_id: brief-2026-11-08-openremote-auth-vuln
event_id: brief-2026-11-08-openremote-auth-vuln
revision: 1
activity_at: "2026-11-08T15:30:35Z"
title: 'OpenRemote: Improper authorization in admin endpoints (CVE-2026-124436)'
slug: 2026-11-openremote-auth-vuln
description: OpenRemote versions prior to 1.32.2 contain an authorization flaw allowing realm administrators to perform unauthorized modifications of global resources by accessing restricted administrative endpoints.
date: "2026-11-08T15:30:35Z"
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
  validation_status: Ready for deployment validation
cpes:
  - cpe:2.3:a:openremote:openremote:*:*:*:*:*:*:*:*
vendors:
  - OpenRemote
products:
  - OpenRemote (< 1.32.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: OpenRemote before 1.32.2 contains an improper authorization vulnerability that allows realm administrators to access and modify global resources by calling admin endpoints lacking super administrator checks.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: Attackers can change the global keycloakUrl ... to redirect other realms' console authentication for credential phishing.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Attackers can change the global keycloakUrl ... to redirect other realms' console authentication for credential phishing.
    confidence_band: high
cves:
  - id: CVE-2026-124436
    cvss: 8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124436
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenRemote instances to version 1.32.2 or later
      owner: IT Operations
      due: 48h
      evidence: OpenRemote before 1.32.2 contains an improper authorization vulnerability
  hunt_leads:
    - lead: Identify unauthorized access attempts or configuration changes to /configuration/manager
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application API audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can change the global keycloakUrl via /configuration/manager
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenRemote to 1.32.2
      owner: IT Operations
      addresses: CVE-2026-124436
      evidence: NVD CVE-2026-124436 advisory
---

OpenRemote versions before 1.32.2 are vulnerable to an improper authorization flaw. Realm administrators can invoke administrative endpoints without sufficient super-administrator validation, granting them control over global system configuration. Confirmed impacts include the modification of the 'keycloakUrl' for credential phishing redirection, malicious CSS injection, map tile replacement, and unauthorized deletion of system logs.

## Impact

Successful exploitation allows a realm administrator to perform unauthorized actions including credential harvesting, content manipulation, and log destruction, potentially leading to persistent account takeover or loss of auditability.

## Recommendation

- Upgrade OpenRemote to version 1.32.2 or later to include the required authorization checks.
- Review system and audit logs for unauthorized requests directed at the '/configuration/manager' endpoint or other administrative API paths if an upgrade cannot be performed immediately.
- Audit current global configuration settings, specifically the 'keycloakUrl' value, to ensure they match expected internal authentication providers.
