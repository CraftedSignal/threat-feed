---
brief_id: brief-2026-11-03-mongodb-mongorestore-auth-bypass
event_id: brief-2026-11-03-mongodb-mongorestore-auth-bypass
revision: 1
activity_at: "2026-11-03T18:05:37Z"
title: 'MongoDB Database Tools: mongorestore privilege escalation (CVE-2026-119675)'
slug: 2026-11-mongodb-mongorestore-auth-bypass
description: A vulnerability in the mongorestore utility allows an attacker to bypass namespace validation by leveraging crafted system.buckets collection names, potentially resulting in unauthorized administrative account creation when run by a privileged operator.
date: "2026-11-03T18:05:37Z"
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
  validation_status: Patch verification required
cpes:
  - cpe:2.3:a:mongodb:database_tools:*:*:*:*:*:*:*:*
vendors:
  - MongoDB
products:
  - MongoDB Database Tools (< 100.20.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A specially crafted collection name can bypass special-collection guards and operator namespace filters, causing a restore to create an unauthorized user-chosen database account, including an account with the root role.
    confidence_band: high
cves:
  - id: CVE-2026-119675
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119675
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DBA Team
  immediate_actions:
    - action: Upgrade MongoDB Database Tools to version 100.20.1 or later
      owner: IT Operations
      due: 72h
      evidence: Issue affects MongoDB Database Tools versions 100.4.0 through versions before 100.20.1
  hunt_leads:
    - lead: Monitor database audit logs for the creation of new users or role assignments occurring shortly after mongorestore execution
      technique_id: T1068
      data_needed:
        - MongoDB Audit Log (authCheck, createRole, createUser)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation causes a restore to create an unauthorized user-chosen database account, including an account with the root role.
  mitigation_plan:
    - priority: immediate
      action: Restrict user-management privileges for database accounts used to trigger mongorestore
      owner: DBA Team
      addresses: CVE-2026-119675
      evidence: Exploitation requires an operator to restore unauthorized user-controlled data using credentials with sufficient user-management privileges
---

CVE-2026-119675 concerns an input validation flaw in MongoDB Database Tools versions 100.4.0 through 100.20.0. The mongorestore utility inconsistently handles the 'system.buckets.' prefix when validating collection names in untrusted database dumps. By exploiting this, an attacker can bypass namespace guards and restore user-controlled data into unauthorized namespaces. If the operator executing the restore process possesses user-management privileges on the destination database, this vulnerability can be leveraged to create unauthorized database accounts, including those with root roles. Notably, filtering the 'admin' namespace is insufficient to mitigate this risk.

## Impact

Successful exploitation allows for the creation of unauthorized database users with elevated privileges, including root access, within the target MongoDB deployment. This requires the victim operator to execute a restore operation from a malicious or compromised dump file while using credentials that permit user management.

## Recommendation

* Patch the MongoDB Database Tools to version 100.20.1 or later on all administrative workstations and CI/CD pipelines used for database maintenance.
* Audit and restrict the permissions of database service accounts used for restore operations; ensure that users performing restore tasks do not hold excessive user-management privileges (e.g., 'userAdmin' or 'userAdminAnyDatabase') unless strictly necessary.
* Avoid restoring database dumps from untrusted or unverified third-party sources.
