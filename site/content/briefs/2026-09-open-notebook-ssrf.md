---
title: SSRF Vulnerability in Open Notebook /api/sources Endpoint
slug: 2026-09-open-notebook-ssrf
description: Open Notebook versions prior to 1.11.0 contain a Server-Side Request Forgery vulnerability allowing authenticated users to probe internal network services and cloud metadata endpoints.
date: "2026-09-13T11:25:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:open_notebook:open_notebook:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-application
  - vulnerability
vendors:
  - Open Notebook
products:
  - Open Notebook (< 1.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Open Notebook before 1.11.0 fails to validate the URL parameter in POST /api/sources endpoint, allowing authenticated users to perform server-side requests to internal services.
    confidence_band: high
cves:
  - id: CVE-2026-90769
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90769
rules:
  - title: Detect CVE-2026-90769 Exploitation - SSRF via /api/sources
    description: Detects exploitation attempts against CVE-2026-90769 where an authenticated user submits internal network or cloud metadata IP addresses in the URL parameter of a POST request to /api/sources.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Open Notebook instances to version 1.11.0
      owner: IT Operations
      due: 48h
      evidence: Open Notebook before 1.11.0 contains a Server-Side Request Forgery (SSRF) vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.11.0
      owner: IT Operations
      addresses: CVE-2026-90769
      evidence: Patch availability for version 1.11.0
---

Open Notebook versions before 1.11.0 contain a Server-Side Request Forgery (SSRF) vulnerability within the POST /api/sources endpoint. This flaw arises from insufficient validation of the 'URL' parameter, which allows an authenticated user to force the application server to perform arbitrary outbound HTTP requests. By manipulating this parameter, an attacker can proxy requests to interact with internal network services, resources bound to localhost, or sensitive cloud metadata services. Because the request originates from the application server itself, it bypasses network-level access controls that might otherwise protect these internal resources. This vulnerability is particularly critical in cloud-hosted environments where metadata services (such as the AWS Instance Metadata Service) can be used to extract sensitive security credentials or instance information.

## Impact

Successful exploitation allows authenticated users to pivot from the application layer into the internal network, potentially accessing restricted management interfaces, services not exposed to the public, or sensitive cloud environment data. This facilitates reconnaissance and potential credential theft, which may lead to further system compromise within the internal infrastructure.

## Recommendation

1. Upgrade Open Notebook to version 1.11.0 or later to implement URL validation on the /api/sources endpoint.
2. Review application logs for unusual POST requests to /api/sources where the 'URL' parameter contains private IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or common metadata endpoints (e.g., 169.254.169.254).
3. Implement network egress filtering on the application server to restrict outbound connections to only necessary external domains.
