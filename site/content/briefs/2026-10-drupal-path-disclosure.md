---
title: Full Path Disclosure Vulnerability in Drupal 11.x-dev
slug: 2026-10-drupal-path-disclosure
description: CVE-2024-45440 is a full path disclosure vulnerability in Drupal 11.x-dev allowing unauthenticated attackers to leak server-side filesystem paths via the authorize.php endpoint.
date: "2026-10-02T16:37:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:drupal:drupal:2023-05-09:*:*:*:*:*:*:*
tags:
  - vulnerability
  - drupal
  - reconnaissance
vendors:
  - Drupal
products:
  - Drupal (11.x-dev)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The flaw enables full path disclosure, allowing attackers to leak the absolute path of the configuration file to an unauthenticated remote attacker.
    confidence_band: high
cves:
  - id: CVE-2024-45440
    cvss: 5.3
    epss: 0.09269
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-W0R1I0G1HT-CVE-2024-45440
rules:
  - title: Detects CVE-2024-45440 Exploitation - Path Disclosure via authorize.php
    description: Detects exploitation attempts targeting the authorize.php endpoint in Drupal 11.x-dev by monitoring for the hash_salt parameter.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or remove vulnerable Drupal 11.x-dev installations
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-45440 vulnerability notice
  enrichment_needed:
    - item: Confirmation of patches released by the Drupal community
      owner: CTI
      reason: To ensure permanent remediation
      evidence: Vulnerability analysis
  hunt_leads:
    - lead: Search logs for unusual access to /core/authorize.php
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Exploit POC instructions
  mitigation_plan:
    - priority: immediate
      action: Restrict access to authorize.php at the web server level
      owner: IT Operations
      addresses: CVE-2024-45440
      evidence: Vulnerability analysis
---

CVE-2024-45440 is a security vulnerability in Drupal 11.x-dev that enables an unauthenticated attacker to perform full path disclosure. The flaw resides within the `core/authorize.php` component. When the application attempts to process the `hash_salt` parameter, an improper execution of `file_get_contents` on a non-existent or misconfigured file can trigger an error response that reveals the absolute path of the Drupal installation on the underlying server. While the vulnerability is classified as medium severity (CVSS 5.3), the exposure of internal filesystem structures provides attackers with reconnaissance data that facilitates more complex, targeted attacks. Publicly available exploit scripts automate the discovery process, increasing the risk for organizations running development or pre-release versions of the Drupal core.

## Attack Chain

1. Attacker identifies a target server running Drupal 11.x-dev.
2. Attacker probes the endpoint `/core/authorize.php` to determine if it is reachable.
3. Attacker submits a specially crafted HTTP request targeting the `hash_salt` parameter.
4. The vulnerable `core/authorize.php` script triggers a `file_get_contents` operation on an invalid file path.
5. The application fails to handle the error properly, generating an error log that includes the full server-side path.
6. The server returns the path information in the HTTP response body to the attacker.
7. Attacker uses the disclosed path information to plan further reconnaissance or exploit attempts against the server infrastructure.

## Impact

Successful exploitation results in the leakage of sensitive internal filesystem paths. While not providing direct remote code execution, this information disclosure is a critical reconnaissance step. It allows adversaries to map server directory structures, facilitating the identification of configuration files, backup files, or other sensitive resources that could be targeted in secondary attacks. The vulnerability affects Drupal 11.x-dev versions.

## Recommendation

1. Identify and upgrade all instances of Drupal 11.x-dev to a patched, stable release that remediates this disclosure flaw.
2. Restrict public access to administrative and installation-related scripts, specifically `core/authorize.php`, if they are not required for normal site operation.
3. Deploy the webserver-level detection rule below to monitor for exploitation attempts against the `authorize.php` endpoint.
4. Review web access logs for 200/500 status codes originating from suspicious query strings containing `hash_salt`.
