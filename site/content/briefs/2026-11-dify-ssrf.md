---
brief_id: brief-2026-11-06-dify-ssrf
event_id: brief-2026-11-06-dify-ssrf
revision: 1
activity_at: "2026-11-06T17:26:35Z"
title: 'Dify: Server-side request forgery (CVE-2026-58141)'
slug: 2026-11-dify-ssrf
description: Dify versions prior to 1.15.0 contain a server-side request forgery (SSRF) vulnerability allowing authenticated users to access internal network services and cloud metadata via misconfigured proxy settings.
date: "2026-11-06T17:26:35Z"
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
  - cpe:2.3:a:dify:dify:*:*:*:*:*:*:*:*
vendors:
  - Dify
products:
  - Dify (< 1.15.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Dify before 1.15.0 contains a server-side request forgery vulnerability that allows any authenticated console user to bypass SSRF protections.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Attackers can use endpoints such as GET /console/api/remote-files/<url>... to reach internal components like the sandbox, internal APIs, and PostgreSQL.
    confidence_band: high
cves:
  - id: CVE-2026-58141
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58141
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Dify to 1.15.0 or later
      owner: IT Operations
      due: 48h
      evidence: Dify before 1.15.0 contains a server-side request forgery vulnerability
  hunt_leads:
    - lead: Identify unusual outbound HTTP traffic from Dify application nodes to internal network segments or cloud metadata IPs (169.254.169.254)
      technique_id: T1595
      data_needed:
        - VPC flow logs
        - Proxy access logs
        - Application egress logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can use... GET /console/api/remote-files/<url>... to reach internal components like... internal APIs.
  mitigation_plan:
    - priority: immediate
      action: Apply patch 1.15.0
      owner: IT Operations
      addresses: CVE-2026-58141
      evidence: Dify before 1.15.0 contains a server-side request forgery vulnerability
---

Dify versions prior to 1.15.0 contain a server-side request forgery (SSRF) vulnerability that permits authenticated console users to bypass security protections. The vulnerability stems from a Squid proxy configuration that lacks destination deny rules and a make_request() helper function that fails to perform independent destination IP validation. 

## Impact

Authenticated attackers can reach internal infrastructure, including sandbox environments, internal APIs, and PostgreSQL databases. On AWS deployments, attackers may leverage this flaw to access the instance metadata service to retrieve IAM credentials. The HTTP Request workflow node further enables unauthorized POST, PUT, and DELETE operations against internal services that rely on network isolation for authorization.

## Recommendation

* Upgrade Dify to version 1.15.0 or later immediately to apply the patch for CVE-2026-58141.
* Audit application logs for abnormal outbound requests originating from the Dify backend.
* Implement stricter network segmentation (egress filtering) for the Dify environment to prevent internal network scanning and unauthorized access to cloud metadata services.
