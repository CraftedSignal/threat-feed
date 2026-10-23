---
brief_id: brief-2026-10-23-georitm-auth-bypass
event_id: brief-2026-10-23-georitm-auth-bypass
revision: 1
activity_at: "2026-10-23T16:37:33Z"
title: 'GEOritm: Unauthenticated information disclosure via REST API (CVE-2026-100903)'
slug: 2026-10-georitm-auth-bypass
description: An authentication bypass vulnerability in the GEOritm REST API allows unauthenticated remote attackers to enumerate fleet assets and retrieve sensitive personal data via the /restapi/objects/obj-groups endpoint.
date: "2026-10-23T16:37:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - information-disclosure
  - api-vulnerability
  - georitm
vendors:
  - ООО НПО Ритм
products:
  - GEOritm (<= 2.45.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability in the POST /restapi/objects/obj-groups method allows an attacker acting remotely without authentication to obtain object associations.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: When combined with the object enumeration method, this vulnerability allows for anonymous deanonymization of the entire fleet of monitored objects.
    confidence_band: high
cves:
  - id: CVE-2026-100903
    cvss: 5.3
    epss: 0.00458
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln.detail/cve-2026-100903
  - https://bdu.fstec.ru/vul/2026-11235
  - https://github.com/4ybrick/CVE-2026-100903/blob/main/ritm_park_enum.sh
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-4YBRICK-CVE-2026-100903&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-100903 Exploitation Attempt
    description: Detects unauthenticated POST requests to the GEOritm /restapi/objects/obj-groups endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for /restapi/objects/obj-groups API monitoring
      owner: Detection Engineering
      due: 24h
      evidence: Public PoC demonstrates exploitation via this specific endpoint
  hunt_leads:
    - lead: Search web server logs for high-frequency POST requests to /restapi/objects/obj-groups
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Enumeration of fleet objects is a hallmark of this exploitation method
  mitigation_plan:
    - priority: immediate
      action: Implement WAF or network-level access control list (ACL) restriction for /restapi/objects/obj-groups
      owner: IT Operations
      addresses: CVE-2026-100903
      evidence: Vulnerability is caused by missing authentication on a public-facing API endpoint
---

GEOritm versions <= 2.45.1 contain a missing authentication vulnerability (CVE-2026-100903) in the POST /restapi/objects/obj-groups endpoint. Exploitation allows remote, unauthenticated attackers to query the API using an 'objectId' parameter to return organizational data, regional associations, and potentially the name and initials of the responsible driver. Enumeration of these identifiers enables deanonymization of monitored fleet objects.

## Impact
Successful exploitation leads to unauthorized information disclosure of fleet telemetry and personally identifiable information (PII). Attackers can systematically enumerate monitored objects to map entire fleets.

## Recommendation
- Restrict network access to the GEOritm REST API to trusted internal management segments.
- Review web server access logs for anomalous, high-volume POST requests to /restapi/objects/obj-groups originating from untrusted IP addresses.
- Monitor for the deployment of enumeration scripts similar to the publicly released 'ritm_park_enum.sh'.
- Verify current version of GEOritm and coordinate with the vendor (ООО НПО Ритм) for remediation paths beyond version 2.45.1.
