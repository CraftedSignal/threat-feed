---
brief_id: brief-2026-11-04-webvirtcloud-auth-bypass
event_id: brief-2026-11-04-webvirtcloud-auth-bypass
revision: 1
activity_at: "2026-11-04T22:10:00Z"
title: 'WebVirtCloud: Unauthorized API access via missing permissions (CVE-2026-122224)'
slug: 2026-11-webvirtcloud-auth-bypass
description: WebVirtCloud versions up to commit bb920b0 suffer from missing authorization on Django REST Framework API endpoints, allowing authenticated users to perform unauthorized VM migration and domain manipulation.
date: "2026-11-04T22:10:00Z"
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
  validation_status: Source confirmed vulnerability in MigrateViewSet and CreateInstanceViewSet
cpes:
  - cpe:2.3:a:webvirtcloud:webvirtcloud:*:*:*:*:*:*:*:*
vendors:
  - WebVirtCloud
products:
  - WebVirtCloud (<= bb920b0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can send requests to /api/v1/migrate/ or the compute instance create endpoint to migrate or undefine other users virtual machines and create volumes and domains on any compute host.
    confidence_band: high
cves:
  - id: CVE-2026-122224
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122224
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  hunt_leads:
    - lead: Identify authenticated requests to /api/v1/migrate/ or instance creation endpoints originating from low-privileged user sessions
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can send requests to /api/v1/migrate/ or the compute instance create endpoint
  mitigation_plan:
    - priority: immediate
      action: Apply security patch or restrict API access to the affected endpoints
      owner: IT Operations
      addresses: CVE-2026-122224
      evidence: Missing authorization vulnerability in Django REST Framework endpoints
---

WebVirtCloud versions up to commit bb920b0 fail to define `permission_classes` for the `MigrateViewSet` and `CreateInstanceViewSet` Django REST Framework endpoints. This results in the API defaulting to `AllowAny`, permitting authenticated users to access administrative functions. An attacker can exploit this to migrate virtual machines, undefine existing virtual machines, and create new volumes or domains on any compute host managed by the application.

## Impact
Impact includes unauthorized control over virtualized compute resources. Attackers can migrate or delete virtual machines and provision unauthorized infrastructure on compute hosts, potentially leading to service disruption or unauthorized resource consumption.

## Recommendation
- Audit WebVirtCloud installations to identify instances using affected versions up to commit bb920b0.
- Implement access control list (ACL) restrictions at the web application firewall or reverse proxy level for the `/api/v1/migrate/` and compute instance creation endpoints until a patch is applied.
- Restrict access to the API to trusted management subnets.
