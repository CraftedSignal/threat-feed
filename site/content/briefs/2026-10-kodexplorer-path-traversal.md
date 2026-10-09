---
title: Path Traversal Vulnerability in KodExplorer (CVE-2026-104081)
slug: 2026-10-kodexplorer-path-traversal
description: KodExplorer before version 4.55 contains a path traversal vulnerability in the unzip_pre_name() function that allows authenticated attackers to perform arbitrary file overwrites and achieve remote code execution.
date: "2026-10-09T15:30:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kodexplorer:kodexplorer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - web-application
vendors:
  - KodExplorer
products:
  - KodExplorer (< 4.55)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can upload a malicious ZIP archive with traversal sequences to overwrite arbitrary files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: enabling stored XSS that leads to admin account takeover and subsequent remote code execution
    confidence_band: high
cves:
  - id: CVE-2026-104081
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104081
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade KodExplorer to version 4.55 or later
      owner: IT Operations
      due: 24h
      evidence: Source document identifies version 4.55 as the patch.
  mitigation_plan:
    - priority: immediate
      action: Upgrade KodExplorer to version 4.55
      owner: IT Operations
      addresses: CVE-2026-104081
      evidence: NVD vulnerability notice.
---

KodExplorer versions prior to 4.55 are susceptible to a path traversal vulnerability located within the unzip_pre_name() function in app/function/helper.function.php. The vulnerability arises from an insufficient sanitization implementation using a single non-recursive str_replace() call, which can be bypassed by attackers using crafted path sequences such as "....//". Furthermore, the application's implementation of the PclZip library in KodArchive.class.php fails to utilize the necessary PCLZIP_OPT_EXTRACT_DIR_RESTRICTION, allowing the traversal sequences to escape the intended directory boundaries. Authenticated attackers can leverage this flaw by uploading a maliciously crafted ZIP archive containing traversal filenames. This enables the overwriting of critical core assets, specifically JavaScript files, facilitating stored XSS. By targeting administrative sessions, an attacker can gain unauthorized access to the application, subsequently enabling the upload of arbitrary PHP files and achieving remote code execution.

## Attack Chain

1. Attacker authenticates to the target KodExplorer instance.
2. Attacker crafts a ZIP archive containing files with traversal path names (e.g., "....//....//index.php").
3. Attacker uploads the malicious ZIP archive via the application's file management interface.
4. The application processes the archive using the vulnerable unzip_pre_name() function.
5. The traversal bypass occurs, and the PclZip library executes the file extraction without directory restrictions.
6. The attacker overwrites a core JavaScript asset file with malicious XSS payloads.
7. A victim administrator accesses the compromised JavaScript asset, triggering the stored XSS.
8. Attacker leverages the hijacked administrator session to upload a webshell for remote code execution.

## Impact

Successful exploitation allows an authenticated attacker to gain administrative control over the KodExplorer instance. By overwriting core files and achieving remote code execution, attackers can gain full control over the underlying server environment, potentially leading to data exfiltration, service disruption, and lateral movement within the network.

## Recommendation

Prioritized actions for security teams:
- Update KodExplorer to version 4.55 or later immediately to patch the vulnerable unzip_pre_name() function.
- Review web server access logs for anomalous POST requests to file upload endpoints originating from authenticated user accounts.
- Audit file system integrity for modifications to core application JavaScript files located in the web root.
