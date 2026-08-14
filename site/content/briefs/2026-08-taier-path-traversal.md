---
title: Path Traversal Vulnerability in DTStack Taier
slug: 2026-08-taier-path-traversal
description: DTStack Taier 1.4.0 is susceptible to a remote path traversal vulnerability (CVE-2026-19762) in the Chunk-Check endpoint, allowing unauthenticated attackers to manipulate file paths.
date: "2026-08-14T02:06:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
vendors:
  - DTStack
products:
  - Taier (1.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument Name results in path traversal. The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19762
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19762
  - https://github.com/DTStack/Taier/issues/1203
rules:
  - title: Detect CVE-2026-19762 Exploitation - Path Traversal in Taier Chunk-Check
    description: Detects exploitation attempts against the Taier Chunk-Check endpoint by monitoring for path traversal sequences in the Name parameter.
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
    - action: Deploy WAF or web server rules to inspect for path traversal strings targeting Taier endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-19762 exploit is public
  mitigation_plan:
    - priority: immediate
      action: Identify and restrict access to Taier 1.4.0 instances
      owner: IT Operations
      addresses: CVE-2026-19762
      evidence: Source description of vulnerability
---

A path traversal vulnerability exists in DTStack Taier 1.4.0, specifically within the Chunk-Check endpoint handled by the FileChunkController.java file. An unauthenticated remote attacker can exploit the 'Paths.ge' function by manipulating the 'Name' argument. This flaw allows the attacker to bypass directory restrictions and access arbitrary files on the underlying filesystem. Publicly available exploit material exists for this vulnerability, increasing the risk of exploitation. Given the potential for unauthorized file access, organizations utilizing DTStack Taier 1.4.0 are advised to prioritize remediation.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to read arbitrary files from the server hosting the Taier application. This can lead to the exposure of sensitive configuration files, credentials, or application data, potentially compromising the integrity and confidentiality of the host environment.

## Recommendation

* Upgrade DTStack Taier to a patched version once available to address CVE-2026-19762.
* Implement strict input validation on the 'Name' argument within the 'FileChunkController' endpoint to prevent path traversal characters such as '../'.
* Monitor web server logs for requests to the 'Chunk-Check' endpoint containing path traversal sequences or anomalous filename parameters.
