---
brief_id: brief-2026-10-31-simpleform-rce
event_id: brief-2026-10-31-simpleform-rce
revision: 1
activity_at: "2026-10-31T11:56:58Z"
title: 'SimpleForm: Arbitrary file upload remote code execution (CVE-2026-118235)'
slug: 2026-10-simpleform-rce
description: An unauthenticated remote code execution vulnerability in the SimpleForm WordPress plugin (<= 3.10.2) allows attackers to bypass file validation via trailing-dot filenames and exploit publicly exposed nonces.
date: "2026-10-31T11:56:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:simpleform:simpleform:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - remote-code-execution
  - file-upload
  - cve-2026-118235
vendors:
  - SimpleForm
products:
  - SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications (<= 3.10.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-118235
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118235
rules:
  - title: Detects CVE-2026-118235 Exploitation - Arbitrary File Upload via SimpleForm
    description: Detects potential exploitation of CVE-2026-118235 by identifying file upload requests containing filenames ending with a dot, which is a known bypass technique for the handle_upload function.
    platform: sigma
    severity: critical
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
    - action: Patch SimpleForm plugin to a version > 3.10.2
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions up to and including 3.10.2 are vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to the SimpleForm handle_upload function combined with suspicious file extensions or trailing dot anomalies.
      technique_id: T1190
      data_needed:
        - web_server_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The handle_upload function in the plugin contains the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SimpleForm plugin to the latest secure version.
      owner: IT Operations
      addresses: CVE-2026-118235
      evidence: NVD advisory for CVE-2026-118235.
---

The SimpleForm plugin for WordPress is vulnerable to arbitrary file upload (CVE-2026-118235) due to a flaw in the 'handle_upload' function. The vulnerability allows unauthenticated attackers to bypass extension and MIME type validation by utilizing filenames ending with a dot. Furthermore, the nonce required for the upload request is printed in the data-nonce attribute of every public form, enabling unauthenticated access. Successful exploitation can lead to remote code execution.

## Impact

Successful exploitation allows unauthenticated attackers to upload executable files to the WordPress server, potentially resulting in full system compromise via remote code execution.

## Recommendation

Update the 'SimpleForm - Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications' plugin to a version released after 3.10.2. Until patching is completed, consider disabling the plugin or restricting access to the associated upload endpoints if the site functionality permits.
