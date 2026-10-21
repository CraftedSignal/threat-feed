---
brief_id: brief-2026-10-21-momo-tommy-auth-bypass
event_id: brief-2026-10-21-momo-tommy-auth-bypass
revision: 1
activity_at: "2026-10-21T19:16:09Z"
title: 'MomoTommy file-management-system: Authentication bypass (CVE-2026-114261)'
slug: 2026-10-momo-tommy-auth-bypass
description: A missing authentication vulnerability in the MomoTommy file-management-system Files API allows remote attackers to manipulate request arguments to gain unauthorized access to file operations.
date: "2026-10-21T19:16:09Z"
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
  validation_status: No vendor patch available; requires manual environment audit.
cpes:
  - cpe:2.3:a:momotommy:file-management-system:*:*:*:*:*:*:*:*
vendors:
  - MomoTommy
products:
  - file-management-system
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument Request results in missing authentication. The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-114261
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114261
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all deployments of MomoTommy file-management-system
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects a specific public-facing web component with no patch available.
  hunt_leads:
    - lead: Unauthenticated POST, PUT, DELETE, or GET requests to the FileController endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability affects the index, store, update, and destroy methods of FileController.php.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the application
      owner: IT Operations
      addresses: CVE-2026-114261
      evidence: No vendor fix exists; network segmentation is the primary mitigation.
---

A vulnerability exists in the MomoTommy file-management-system (commit dc9ce1bf27f94b23d906cb1e86ce374dc94ca5df) within the Files API component. Specifically, the 'index', 'store', 'update', and 'destroy' functions in 'app/Http/Controllers/FileController.php' fail to properly validate authentication when specific request arguments are manipulated. This vulnerability allows for unauthenticated remote access to file management operations. As the project does not use formal versioning and has not responded to vulnerability reports, there is no vendor patch available.

## Impact
Remote unauthenticated attackers can perform unauthorized file operations, including creating, reading, updating, and deleting files, by bypassing the authentication controls in the Files API.

## Recommendation
- Identify all instances of MomoTommy file-management-system in the environment.
- Implement network-level access controls to restrict access to the application to trusted internal segments only.
- Apply WAF rules to inspect HTTP requests directed at the 'app/Http/Controllers/FileController.php' logic if feasible.
- Monitor application access logs for unexpected access to the Files API endpoints, particularly from unauthorized or external IP addresses.
