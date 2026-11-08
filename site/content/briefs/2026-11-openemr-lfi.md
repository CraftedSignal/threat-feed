---
brief_id: brief-2026-11-08-openemr-lfi
event_id: brief-2026-11-08-openemr-lfi
revision: 1
activity_at: "2026-11-08T23:20:40Z"
title: 'OpenEMR: Local file inclusion and remote code execution (CVE-2026-124467)'
slug: 2026-11-openemr-lfi
description: OpenEMR versions prior to 8.4.0 contain a local file inclusion vulnerability in the ESign router, allowing authenticated attackers to execute arbitrary code via a malicious file upload.
date: "2026-11-08T23:20:40Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - lfi
  - rce
  - web-vulnerability
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can upload a PHP file named Controller.php, then request interface/esign/index.php with a traversing module parameter to include it and execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-124467
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124467
rules:
  - title: Detect CVE-2026-124467 Exploitation - LFI via ESign module parameter
    description: Detects exploitation attempts against CVE-2026-124467 by identifying path traversal patterns within the module parameter of the ESign router.
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
    - action: Upgrade OpenEMR to version 8.4.0 or later
      owner: IT Operations
      due: 48h
      evidence: OpenEMR before 8.4.0 contains a local file inclusion
  hunt_leads:
    - lead: Identify file uploads to the fax module temporary directory
      technique_id: T1190
      data_needed:
        - File system events or application logs showing file writes within the OpenEMR upload path
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: the fax module faxProcessUploads writes attacker-named files to a predictable temp path
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.4.0
      owner: IT Operations
      addresses: CVE-2026-124467
      evidence: OpenEMR before 8.4.0 contains a local file inclusion
---

OpenEMR versions before 8.4.0 contain a local file inclusion (LFI) vulnerability in the ESign router component located in `library/ESign/Router.php`. The vulnerability arises because the `module` parameter is passed into a `require_once` statement without sanitization. Additionally, the application's fax module (`faxProcessUploads`) allows the writing of files with attacker-controlled content to a predictable temporary path without validating file extensions. An authenticated attacker can combine these flaws to upload a malicious PHP file masquerading as a controller, and then trigger its execution by requesting the ESign index file with a path-traversal payload in the `module` parameter.

## Attack Chain

1. Attacker authenticates to the OpenEMR instance.
2. Attacker interacts with the fax module via `faxProcessUploads`.
3. Attacker uploads a file containing malicious PHP code.
4. The application saves the file to a predictable temporary directory on the server.
5. Attacker makes a request to `interface/esign/index.php`.
6. Attacker provides a path-traversal string in the `module` parameter to point to the uploaded PHP file.
7. `library/ESign/Router.php` executes `require_once` on the malicious file, resulting in remote code execution.

## Impact

Successful exploitation allows an authenticated attacker to achieve remote code execution on the underlying server, potentially leading to full system compromise.

## Recommendation

- Upgrade OpenEMR to version 8.4.0 or later immediately to address the vulnerabilities in the ESign router and fax module.
- Review access logs for requests to `interface/esign/index.php` containing path traversal sequences (e.g., `../`, `..%2f`).
- Audit the temporary directory used by the fax module for unexpected `.php` files.
