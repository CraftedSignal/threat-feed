---
brief_id: brief-2026-11-08-magento-wysiwyg-upload
event_id: brief-2026-11-08-magento-wysiwyg-upload
revision: 1
activity_at: "2026-11-08T14:45:52Z"
title: 'Adobe Commerce: Unrestricted file upload vulnerability (CVE-2026-48356)'
slug: 2026-11-magento-wysiwyg-upload
description: CVE-2026-48356 is an unrestricted file upload vulnerability in Adobe Commerce REST and WYSIWYG endpoints, enabling potential remote code execution via the pub/media directory.
date: "2026-11-08T14:45:52Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:adobe:commerce:2.4.4:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.5:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.6:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.7:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.8:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.9:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce_b2b:1.3.3:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce_b2b:1.3.4:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce_b2b:1.4.2:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce_b2b:1.5.2:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce_b2b:1.5.3:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:magento:2.4.6:*:*:*:open_source:*:*:*
  - cpe:2.3:a:adobe:magento:2.4.7:*:*:*:open_source:*:*:*
  - cpe:2.3:a:adobe:magento:2.4.8:*:*:*:open_source:*:*:*
  - cpe:2.3:a:adobe:magento:2.4.9:-:*:*:open_source:*:*:*
  - cpe:2.3:a:adobe:i\/o_events:*:*:*:*:*:commerce:*:*
vendors:
  - Adobe
products:
  - Adobe Commerce (2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unrestricted file upload to pub/media in Adobe Commerce / Magento 2.4.x REST and WYSIWYG.
    confidence_band: high
cves:
  - id: CVE-2026-48356
    cvss: 9.3
    epss: 0.47472
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48356
  - https://github.com/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-MAGENTO_CVE_2026_48356_DETECT
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-MAGENTO_CVE_2026_48356_DETECT&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-48356 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-48356 by monitoring for HTTP POST requests to the WYSIWYG image upload REST endpoint.
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
    - SOC
  immediate_actions:
    - action: Patch all Adobe Commerce instances to the latest available version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-48356 high severity and availability of public exploit.
  hunt_leads:
    - lead: Identify successful POST requests to the WYSIWYG upload endpoint followed by unauthorized file access in pub/media.
      technique_id: T1190
      data_needed:
        - webserver access logs
        - file system audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows uploading to pub/media directory.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF blocking for POST requests to /rest/V1/wysiwyg/image/upload if immediate patching is not possible.
      owner: IT Operations
      addresses: CVE-2026-48356
      evidence: Public exploit targeting this specific REST endpoint.
---

CVE-2026-48356 is a high-severity (CVSS 9.3) unrestricted file upload vulnerability affecting Adobe Commerce versions 2.4.4 through 2.4.9. The vulnerability exists within the REST and WYSIWYG upload endpoints, allowing unauthenticated attackers to upload files to the 'pub/media' directory. Publicly available exploit PoCs demonstrate the ability to probe for these endpoints and successfully upload files, which may be leveraged for remote code execution.

## Impact

Successful exploitation allows for the upload of arbitrary files to the web server, which can be used to achieve remote code execution if the uploaded files (e.g., PHP scripts) are accessible and executable via the web interface.

## Recommendation

* Inventory all Adobe Commerce instances and verify the current version.
* Patch or update Adobe Commerce instances immediately to the latest secure version provided by Adobe.
* Monitor web server access logs for unusual requests to '/rest/V1/wysiwyg/image/upload' or other REST API endpoints.
* Restrict access to administrative and API endpoints via firewall or web application firewall (WAF) rules.
