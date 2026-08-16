---
title: Arbitrary File Deletion in ProSolution WP Client Plugin
slug: 2026-08-prosolution-wp-file-deletion
description: An unauthenticated arbitrary file deletion vulnerability in the ProSolution WP Client plugin allows attackers to remove critical WordPress configuration files, potentially facilitating remote code execution.
date: "2026-08-16T06:24:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - arbitrary-file-deletion
  - vulnerability
vendors:
  - ProSolution
products:
  - WP Client (2.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit this by poisoning a session via the proSol_fileUploadModalProcess handler and subsequently triggering a deletion request.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.002
    technique_name: 'Data Manipulated: Stored Data Manipulation'
    evidence: This makes it possible for unauthenticated attackers to delete arbitrary files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-14524
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14524
rules:
  - title: Detect CVE-2026-14524 - Potential File Deletion Attempt
    description: Detects exploitation attempts against ProSolution WP Client by monitoring for sequenced calls to the vulnerable handler and file deletion endpoint.
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
    - action: Patch WP Client plugin to version 2.0.9 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web logs for POST requests to proSol_fileDeleteProcess containing path traversal characters like ../
      technique_id: T1565.002
      data_needed:
        - webserver_logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source states arbitrary file deletion occurs due to insufficient path validation
  mitigation_plan:
    - priority: immediate
      action: Disable ProSolution WP Client plugin until patched
      owner: IT Operations
      addresses: CVE-2026-14524
      evidence: Plugin is the source of the vulnerability
---

The ProSolution WP Client plugin for WordPress versions 2.0.8 and earlier contains a critical security vulnerability, CVE-2026-14524. The flaw exists within the proSol_fileDeleteProcess function, which lacks adequate path validation. This oversight allows an unauthenticated attacker to manipulate file deletion requests to remove arbitrary files from the web server's filesystem.

The vulnerability is chained by first interacting with the proSol_fileUploadModalProcess handler to inject a path-traversal payload into the user session. Once the session is poisoned using the plugin's frontend nonce, an attacker can trigger the proSol_fileDeleteProcess function to target specific files. Successful deletion of critical files like wp-config.php can force a WordPress site into a re-installation state or trigger other application behaviors that lead to remote code execution. Defenders should prioritize updating the plugin to the latest patched version or disabling the component if an immediate update is not feasible.

## Impact

Successful exploitation of CVE-2026-14524 allows for the deletion of any file accessible to the web server process. In a WordPress environment, this typically results in the removal of configuration files like wp-config.php, which can lead to site takeover, loss of data integrity, and remote code execution if the application is subsequently re-installed or misconfigured by the attacker.

## Recommendation

* Update the ProSolution WP Client plugin to the latest available version containing a patch for CVE-2026-14524.
* Monitor web server access logs for anomalous POST requests directed at plugin handlers proSol_fileUploadModalProcess and proSol_fileDeleteProcess.
* Audit filesystem integrity for critical WordPress configuration files like wp-config.php, particularly on internet-facing WordPress instances.
* Use the webserver log source to identify and block unauthorized access attempts if patching is delayed.
