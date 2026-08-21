---
title: Authorization Bypass in Reconmap Report Preview Endpoint
slug: 2026-08-reconmap-auth-bypass
description: An improper [AllowAnonymous] attribute in Reconmap's ReportsController allows unauthenticated remote attackers to perform enumeration of sensitive penetration testing engagement data by walking sequential project IDs.
date: "2026-08-21T11:23:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - reconmap
  - cve-2026-77767
vendors:
  - Reconmap
products:
  - Reconmap
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Because the id is the auto-increment primary key of the project table, an unauthenticated remote caller can walk sequential ids to retrieve the engagement details and client organisation of every project on the instance.
    confidence_band: high
cves:
  - id: CVE-2026-77767
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77767
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Reconmap instance to version containing fix for CVE-2026-77767.
      owner: IT Operations
      due: 72h
      evidence: NVD vulnerability disclosure.
  hunt_leads:
    - lead: Identify high-frequency enumeration patterns targeting report preview endpoints in webserver logs.
      technique_id: T1592
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes that sequential ID walking reveals data.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to report preview API endpoints via WAF.
      owner: IT Operations
      addresses: CVE-2026-77767
      evidence: Authorization bypass allows unauthenticated access.
---

Reconmap contains an authorization bypass vulnerability (CVE-2026-77767) located within the API implementation of the report preview functionality. The application's global fallback authorization policy, defined in apps/api/app/Program.cs, is intended to enforce administrative role requirements. However, the PreviewReport action in apps/api/app/Controllers/ReportsController.cs is incorrectly decorated with an [AllowAnonymous] attribute, which explicitly opts the endpoint out of this protection.

The vulnerability allows an unauthenticated remote attacker to access the report preview functionality without performing any project membership or role-based access checks. Because the endpoint identifies projects using their auto-incrementing primary key, an attacker can programmatically iterate through these IDs to extract the names, descriptions, and client organization details for all projects hosted on an instance. The endpoint also returns distinct error codes (404) for non-existent IDs, facilitating the discovery of valid project ranges. This impact is significant as Reconmap is used to store sensitive penetration-testing engagement data.

## Impact

Successful exploitation allows for the large-scale, automated exfiltration of sensitive client information, including addresses, URLs, and specific penetration-testing engagement descriptions. Because the underlying IDs are sequential, the total dataset of an organization's engagements and associated client records is at risk of full disclosure.

## Recommendation

Prioritize patching the affected Reconmap installation to remediate CVE-2026-77767. If immediate patching is not possible, implement WAF or network-level access controls to restrict access to the /api/reports/preview/ (or equivalent) endpoint to authenticated internal network ranges. Monitor webserver logs for high volumes of 404 responses or sequential requests to report preview endpoints originating from single IP addresses, which indicates an enumeration attempt.
