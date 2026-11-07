---
brief_id: brief-2026-11-07-keycloak-rce
event_id: brief-2026-11-07-keycloak-rce
revision: 1
activity_at: "2026-11-07T16:55:12Z"
title: 'Keycloak: Remote Code Execution in client management component (CVE-2026-120984)'
slug: 2026-11-keycloak-rce
description: An authenticated attacker with client management permissions can exploit a session attribute flaw in Keycloak to upload and execute arbitrary JavaScript policies on the server.
date: "2026-11-07T16:55:12Z"
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
  validation_status: Needs vendor patch release for remediation
cpes:
  - cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows an authenticated attacker with client management permissions to bypass security controls and upload a malicious JavaScript policy, which is then executed on the server when an authorization request is made.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Successful exploitation could allow the attacker to run arbitrary code on the server, potentially compromising the entire system.
    confidence_band: high
cves:
  - id: CVE-2026-120984
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120984
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit administrative accounts with client management permissions
      owner: SOC
      due: 24h
      evidence: Vulnerability requires authenticated attacker with client management permissions
  hunt_leads:
    - lead: Identify unusual policy uploads or modifications in Keycloak authorization service logs
      technique_id: T1059
      data_needed:
        - Keycloak audit logs
        - Application server request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves uploading malicious JavaScript policy to the authorization service
  mitigation_plan:
    - priority: immediate
      action: Apply security patch for CVE-2026-120984 when released by Red Hat
      owner: IT Operations
      addresses: CVE-2026-120984
      evidence: Vendor patch is required to resolve the underlying session attribute flaw
---

A vulnerability exists in the Keycloak client management component where authorization services fail to clear an internal session attribute when a client is created or imported with authorization services enabled. This flaw allows an authenticated user with client management privileges to inject and execute arbitrary JavaScript policies during an authorization request. Successful exploitation leads to remote code execution on the server.

## Impact

An authenticated attacker can execute arbitrary JavaScript on the Keycloak server, potentially leading to full system compromise.

## Recommendation

- Identify all Keycloak instances within the organization.
- Review administrative logs for accounts with client management permissions that have recently created or imported clients.
- Monitor for authorization service policy modifications or the addition of suspicious JavaScript policies.
- Upgrade Keycloak to the vendor-provided patched version once available to address CVE-2026-120984.
