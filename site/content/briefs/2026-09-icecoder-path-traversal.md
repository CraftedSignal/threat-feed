---
title: Path Traversal Vulnerability in ICEcoder (CVE-2026-64836)
slug: 2026-09-icecoder-path-traversal
description: ICEcoder versions 8.1 and earlier are vulnerable to path traversal via a logic error in the file-control endpoint, enabling authenticated attackers to perform arbitrary file reads, writes, and deletions.
date: "2026-09-10T15:09:14Z"
lastmod: "2026-09-10T15:09:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:icecoder:icecoder:*:*:*:*:*:*:*:*
vendors:
  - ICEcoder
products:
  - ICEcoder (<= 8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ICEcoder versions through 8.1 contain a path traversal vulnerability in the file-control endpoint.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation allows for the reading, writing, or deletion of sensitive files, potentially leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can use path traversal sequences in oldFileName to move files writable by the PHP process into the web-accessible project directory, disclosing file contents.
    confidence_band: high
cves:
  - id: CVE-2026-64836
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64836
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64838
rules:
  - title: Detects CVE-2026-64836 Exploitation - Path Traversal in ICEcoder
    description: Detects attempted path traversal via the file-control endpoint in ICEcoder by monitoring for traversal sequences in the file parameter.
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
    - action: Deploy the Sigma rule to detect path traversal attempts targeting the file-control endpoint
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-64836 vulnerability details
  hunt_leads:
    - lead: Search logs for unusual file paths in requests to /file-control
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Logic error in confinement check allows access to arbitrary paths
  mitigation_plan:
    - priority: medium
      action: Restrict access to the ICEcoder file-control endpoint until a patch is applied
      owner: IT Operations
      addresses: CVE-2026-64836
      evidence: Vulnerability reported in versions through 8.1
updates:
  - at: "2026-09-10T15:09:34Z"
    level: L2
    summary: added coverage for ICEcoder (<= 8.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-64838
---

CVE-2026-64836 is a path traversal vulnerability affecting ICEcoder up to and including version 8.1. The flaw exists within the file-control endpoint, specifically due to a logic error in the File::check() validation function. This function attempts to verify that requested file paths remain within the defined document root by comparing realpath() results to boolean true, a comparison that consistently fails. As a result, the confinement check is bypassed. An authenticated attacker can exploit this by submitting traversal sequences (e.g., ../) or absolute paths in the file parameter. Successful exploitation allows for the reading, writing, or deletion of sensitive files on the underlying filesystem, potentially leading to remote code execution or complete system compromise. Organizations running these versions should restrict access to the file-control endpoint or upgrade to a remediated version once available.

## Attack Chain

1. Attacker gains authenticated access to the ICEcoder web interface.
2. Attacker identifies the file-control endpoint as a target for file interaction.
3. Attacker crafts an HTTP request targeting the file parameter.
4. Attacker inserts directory traversal sequences or absolute file paths into the file parameter.
5. The server-side File::check() function executes but fails to properly validate the input due to the logic error.
6. The application processes the request, applying the operation (read, write, or delete) to the targeted file path.
7. Attacker achieves unauthorized file access, modification, or destruction outside the intended document root.

## Impact

Successful exploitation allows authenticated attackers to escape the application's document root, leading to unauthorized access to sensitive configuration files, source code, or system binaries. Depending on the environment, an attacker could delete essential system files or write malicious web shells to attain remote code execution, threatening the integrity and availability of the host server.

## Recommendation

* Deploy the Sigma rule below to monitor for suspicious path traversal patterns in web server logs targeting the ICEcoder file-control endpoint.
* Restrict network access to the ICEcoder instance to trusted IP ranges only.
* Monitor file system integrity for modifications in directories outside the intended ICEcoder web root.
