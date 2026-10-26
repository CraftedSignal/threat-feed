---
brief_id: brief-2026-10-26-rhaphp-ssrf
event_id: brief-2026-10-26-rhaphp-ssrf
revision: 1
activity_at: "2026-10-26T11:41:40Z"
title: 'RhaPHP: Server-side request forgery (CVE-2026-116256)'
slug: 2026-10-rhaphp-ssrf
description: An SSRF vulnerability in the RhaPHP Mp Module Media Proxy allows remote attackers to perform unauthorized requests via the url argument in the image function.
date: "2026-10-26T11:41:40Z"
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
cpes:
  - cpe:2.3:a:geesondog:rhaphp:*:*:*:*:*:*:*:*
vendors:
  - geesondog
products:
  - RhaPHP (<= 7ae639ccf8dcb627faace096d030bd4cb4cfb905)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument url results in server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-116256
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116256
rules:
  - title: Detect CVE-2026-116256 Exploitation - SSRF via RhaPHP Mp Module
    description: Detects exploitation attempts against CVE-2026-116256 by identifying requests to the vulnerable Show.php controller with suspicious URL patterns.
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
    - action: Deploy the provided Sigma rule to web server access logs to identify SSRF attempts targeting RhaPHP.
      owner: Detection Engineering
      due: 48h
      evidence: Public exploit availability and potential for internal network discovery.
  hunt_leads:
    - lead: Search web server logs for high volumes of requests to /application/mp/controller/Show.php
      technique_id: T1190
      data_needed:
        - web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The SSRF vulnerability is triggered via the Show.php controller.
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering and WAF rules to sanitize or block requests containing local IP addresses or suspicious protocols in URL parameters.
      owner: IT Operations
      addresses: CVE-2026-116256
      evidence: The product has no official patch for this vulnerability.
---

CVE-2026-116256 describes a server-side request forgery (SSRF) vulnerability in the RhaPHP application, specifically within the Mp Module Media Proxy component. The vulnerability resides in the 'image' function of the file 'application/mp/controller/Show.php'. A remote attacker can trigger this vulnerability by manipulating the 'url' argument, which lacks sufficient validation. Public exploit material exists for this issue. RhaPHP uses a rolling release model, and the vendor has not provided a patch.

## Impact

An attacker can leverage this SSRF vulnerability to make arbitrary requests from the RhaPHP server, potentially interacting with internal services, metadata endpoints, or other network-accessible resources that are not exposed to the public internet.

## Recommendation

1. Inventory all instances of RhaPHP within the environment.
2. Implement strict egress filtering on the host running RhaPHP to prevent the application from making requests to sensitive internal subnets or cloud provider metadata services (e.g., 169.254.169.254).
3. Deploy WAF rules to inspect HTTP GET/POST requests targeting 'application/mp/controller/Show.php' and flag/block requests where the 'url' parameter contains suspicious schemes (e.g., file://, dict://) or internal IP addresses.
