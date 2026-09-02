---
title: CVE-2026-84702 Path Traversal in Facefusion
slug: 2026-09-facefusion-path-traversal
description: An unauthenticated path traversal vulnerability in Facefusion versions 3.6.1 and earlier allows remote attackers to perform arbitrary file writes via malicious job identifiers.
date: "2026-09-02T03:10:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:facefusion:facefusion:*:*:*:*:*:*:*:*
vendors:
  - Facefusion
products:
  - Facefusion (<= 3.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can supply traversal sequences in the job identifier parameter through the unauthenticated HTTP API to create files at arbitrary locations.
    confidence_band: high
cves:
  - id: CVE-2026-84702
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84702
rules:
  - title: Detects CVE-2026-84702 Exploitation - Path Traversal in Job Identifier
    description: Detects HTTP requests containing directory traversal sequences in parameters likely associated with job identifiers in Facefusion
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
    - IT Operations
  immediate_actions:
    - action: Inventory all Facefusion instances and verify versioning
      owner: IT Operations
      due: 24h
      evidence: Source reporting vulnerability affects <= 3.6.1
  hunt_leads:
    - lead: Search web logs for path traversal patterns in Facefusion API traffic
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source states traversal sequences are used in the job identifier parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade Facefusion to a patched version when available
      owner: IT Operations
      addresses: CVE-2026-84702
      evidence: NVD vulnerability report
---

Facefusion versions up to and including 3.6.1 contain a critical path traversal vulnerability within the `get_job_file_name` function. The application fails to properly sanitize or normalize user-supplied job identifiers provided via the HTTP API. This oversight enables an unauthenticated attacker to inject directory traversal sequences, such as dot-dot-slash patterns, into the job identifier parameter. By manipulating this input, an attacker can escape the intended storage directory and write files to arbitrary locations on the underlying host filesystem. This vulnerability presents a high risk as it facilitates remote code execution if an attacker manages to overwrite sensitive system binaries, configuration files, or startup scripts. Defenders should identify instances of Facefusion in their environment and prioritize upgrading to a patched version once available.

## Impact

Successful exploitation of CVE-2026-84702 allows unauthorized file creation and modification on the target server. This can lead to full system compromise, data corruption, or persistent access for an attacker, depending on the ability to overwrite critical system files or web root contents.

## Recommendation

- Identify all instances of Facefusion running in the environment and verify the version is above 3.6.1.
- Implement strict ingress filtering for the Facefusion HTTP API to prevent untrusted traffic from reaching the endpoint, particularly for deployments exposed to the internet.
- Monitor web server access logs for requests containing directory traversal patterns (e.g., ../ or ..\) within job-related API endpoints.
- Patch Facefusion immediately upon the release of a version addressing CVE-2026-84702.
