---
title: Kunstmaan MediaBundle Blacklist Bypass Leading to Remote Code Execution
slug: 2026-10-kunstmaan-cms-rce
description: An authentication-required blacklist bypass vulnerability in the Kunstmaan MediaBundle allows malicious administrators to upload arbitrary executable files via case-sensitive extension filtering, resulting in remote code execution.
date: "2026-10-07T22:53:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Kunstmaan
products:
  - MediaBundle (< 7.3.2)
  - Bundles-CMS (< 7.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: An authenticated user with access to the admin media section can upload a file that the web server executes as PHP.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The uploaded file is reachable over HTTP without authentication, giving arbitrary code execution as the web server user.
    confidence_band: high
cves:
  - id: CVE-2026-104890
    cvss: 7.2
    epss: 0.00416
references:
  - https://github.com/advisories/GHSA-p279-5wcv-45vq
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Kunstmaan MediaBundle to 7.3.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-104890 vulnerability requires update to 7.3.2
  hunt_leads:
    - lead: Search web server access logs for requests to file extensions in the media directory
      technique_id: T1505.002
      data_needed:
        - webserver log entries
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The uploaded file is reachable over HTTP without authentication.
  mitigation_plan:
    - priority: immediate
      action: Disable PHP engine in media upload directories at the web server level
      owner: IT Operations
      addresses: CVE-2026-104890
      evidence: Workaround suggested by source.
---

Kunstmaan MediaBundle versions prior to 7.3.2 are vulnerable to a remote code execution (RCE) flaw due to improper handling of uploaded file extensions. The application employs a blacklist to prevent the upload of dangerous file types (e.g., .php, .htaccess); however, the validation logic performs a case-sensitive check before the file extension is normalized to lowercase. An attacker with authenticated administrator access to the media management section can bypass this filter by uploading a file with mixed-case extensions (e.g., .pHp). 

The vulnerability is further exacerbated by an incomplete default blacklist that fails to cover common executable extensions such as .phtml, .php5, .phar, .shtml, and .cgi, as well as insecure regex interpolation. Once uploaded, these files are saved to a web-accessible directory and can be executed by the web server. This vulnerability, tracked as CVE-2026-104890, necessitates an immediate upgrade to version 7.3.2 or higher, along with an audit of existing upload directories for previously stored malicious files.

## Attack Chain

1. Attacker gains authentication as a user with administrative access to the media management section of the Kunstmaan CMS.
2. Attacker crafts a malicious payload file with an unconventional casing for an executable extension (e.g., `shell.pHp`).
3. Attacker submits the file via the MediaBundle upload interface.
4. The application performs a case-sensitive regex check against the blacklist, which fails to flag the mixed-case extension.
5. The application normalizes the filename to lowercase, inadvertently turning the file into a valid executable format (e.g., `shell.php`) on the filesystem.
6. The web server processes the uploaded file from the web-accessible directory.
7. The attacker executes the file over HTTP, resulting in remote code execution under the privileges of the web server process.

## Impact

Successful exploitation grants an authenticated administrator arbitrary code execution on the underlying host. This allows for full system compromise, data exfiltration, or lateral movement within the environment. Because the vulnerability requires administrative access, the primary risk is from compromised accounts or malicious insiders.

## Recommendation

* Upgrade the kunstmaan/media-bundle and kunstmaan/bundles-cms packages to version 7.3.2 or later immediately to address CVE-2026-104890.
* Audit the web-accessible media upload directory for existing files containing executable extensions (.php, .phtml, .php5, .phar, .shtml, .cgi) to identify potential prior exploitation.
* Implement web server-level restrictions (e.g., disabling PHP execution in the upload directory) as a compensating control if immediate patching is not possible.
