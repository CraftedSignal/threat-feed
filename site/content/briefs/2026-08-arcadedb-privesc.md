---
title: Authentication Bypass and Privilege Escalation in ArcadeDB Server
slug: 2026-08-arcadedb-privesc
description: ArcadeDB versions 26.7.3 and earlier contain a privilege escalation vulnerability where asynchronous JavaScript commands bypass authorization checks, allowing low-privileged users to achieve server-wide administrative control.
date: "2026-08-18T12:51:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - web-application-vulnerability
  - arcade-db
  - cve-2026-75851
vendors:
  - ArcadeDB
products:
  - ArcadeDB Server (26.7.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: A user with only read access to a single database can submit an asynchronous JavaScript (language=js) command via the /api/v1/command endpoint to run code with unrestricted host access
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The scripting authorization gate to become a no-op... escalating to full administrative control.
    confidence_band: high
cves:
  - id: CVE-2026-75851
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75851
rules:
  - title: Detects CVE-2026-75851 Exploitation - Asynchronous Command Execution with JavaScript
    description: Detects potential exploitation of CVE-2026-75851 by monitoring for JavaScript command execution via the /api/v1/command endpoint with the awaitResponse parameter set to false
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch ArcadeDB Server to version 26.8.1.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 26.8.1.
  hunt_leads:
    - lead: Search logs for POST requests to /api/v1/command containing language=js and awaitResponse=false.
      technique_id: T1059.007
      data_needed:
        - Webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows script injection via these parameters.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ArcadeDB
      owner: IT Operations
      addresses: CVE-2026-75851
      evidence: NVD vulnerability details
---

ArcadeDB server versions 26.7.3 and earlier are vulnerable to a privilege escalation flaw (CVE-2026-75851) due to improper security context propagation in asynchronous command worker threads. When an HTTP command is submitted to the /api/v1/command endpoint with the parameter 'awaitResponse:false', the operation is offloaded to an asynchronous worker thread that fails to bind the current user's principal to the DatabaseContext. Consequently, the application scripting authorization gate treats the command as unauthenticated or authorized, effectively becoming a no-op. An authenticated user possessing only read-only access to a single database can exploit this by injecting arbitrary JavaScript code. This allows for unauthorized administrative actions, such as creating new server-level administrators, resulting in full control over the database environment. This vulnerability was addressed in version 26.8.1.

## Impact

Successful exploitation allows a user with restricted read-only permissions to gain full administrative access to the ArcadeDB instance. This can lead to total loss of confidentiality, integrity, and availability for all data managed by the server, as well as the ability to execute OS-level commands or manipulate server security configurations.

## Recommendation

* Upgrade all instances of ArcadeDB Server to version 26.8.1 or later to remediate CVE-2026-75851.
* Implement strict monitoring for all POST requests sent to the /api/v1/command endpoint to identify suspicious or unexpected asynchronous script submissions.
* Audit existing database users for unusual administrative account creation patterns initiated from non-administrative source sessions.
