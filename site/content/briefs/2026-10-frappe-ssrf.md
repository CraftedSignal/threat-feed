---
brief_id: brief-2026-10-26-frappe-ssrf
event_id: brief-2026-10-26-frappe-ssrf
revision: 1
activity_at: "2026-10-26T13:41:51Z"
title: 'Frappe Builder: Server-side request forgery (CVE-2026-115717)'
slug: 2026-10-frappe-ssrf
description: Frappe Builder versions before 1.36.1 contain an SSRF vulnerability in the convert_to_webp endpoint, allowing authenticated users to probe internal infrastructure or exfiltrate sensitive data.
date: "2026-10-26T13:41:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against NVD summary.
cpes:
  - cpe:2.3:a:frappe:frappe_builder:*:*:*:*:*:*:*:*
vendors:
  - Frappe
products:
  - Frappe Builder (< 1.36.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A low-privilege authenticated user can supply an image_url pointing to an internal address or use DNS rebinding and open redirects to make the server fetch internal network resources or cloud metadata endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-115717
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115717
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Frappe Builder to 1.36.1 or later
      owner: IT Operations
      due: 48h
      evidence: Frappe Builder versions before 1.36.1 contain a server-side request forgery vulnerability.
  hunt_leads:
    - lead: Identify suspicious GET requests to the 'convert_to_webp' endpoint containing private IP ranges or cloud metadata URLs in the 'image_url' parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An authenticated user can supply an image_url pointing to an internal address or use DNS rebinding and open redirects.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.36.1
      owner: IT Operations
      addresses: CVE-2026-115717
      evidence: Frappe Builder versions before 1.36.1 contain a server-side request forgery vulnerability.
---

Frappe Builder versions prior to 1.36.1 are affected by a server-side request forgery (SSRF) vulnerability. The 'convert_to_webp' API endpoint fails to enforce necessary access controls and does not properly validate user-supplied URLs. An attacker with low-privilege authentication can trigger arbitrary GET requests from the server, which follows redirects without validating destination IPs. This can be exploited to reach internal network resources or cloud metadata services. The application may store the resulting image response in a world-readable file, facilitating data exfiltration.

## Impact
Successful exploitation allows authenticated low-privilege users to perform internal network reconnaissance or access sensitive cloud metadata services. Potential data exfiltration may occur if the server-side response is stored in an accessible public file.

## Recommendation
- Upgrade Frappe Builder to version 1.36.1 or later to apply necessary access controls and URL validation to the 'convert_to_webp' endpoint.
- Review access logs for the 'convert_to_webp' endpoint to identify patterns of abnormal internal network probing.
- Restrict the server's egress traffic to internal network ranges or cloud metadata endpoints (e.g., 169.254.169.254).
