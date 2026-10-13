---
title: Unrestricted File Upload in phpwcms Extension Check
slug: 2026-10-phpwcms-unrestricted-upload
description: An unrestricted file upload vulnerability in the Extension Check component of phpwcms allows remote unauthenticated attackers to upload arbitrary files via the POST_name parameter.
date: "2026-10-13T16:36:35Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:slackero:phpwcms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - remote-code-execution
  - file-upload
vendors:
  - slackero
products:
  - phpwcms (<= 1.9.49/1.12.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker can exploit this via the POST_name argument in the include/inc_front/content/cnt23.article.inc.php file.
    confidence_band: high
cves:
  - id: CVE-2026-110025
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110025
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade phpwcms to version 1.9.50 or 1.12.4.
      owner: IT Operations
      due: 48h
      evidence: Vendor recommendation for remediation of CVE-2026-110025.
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to /include/inc_front/content/cnt23.article.inc.php.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability originates from manipulation of input to this specific script.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.9.50 or 1.12.4.
      owner: IT Operations
      addresses: CVE-2026-110025
      evidence: NVD vulnerability details.
---

The slackero phpwcms content management system contains an unrestricted file upload vulnerability in the Extension Check component, identified as CVE-2026-110025. The flaw exists within the file 'include/inc_front/content/cnt23.article.inc.php'. A remote, unauthenticated attacker can exploit this by manipulating the 'POST_name' argument during a request to the affected script. Successful exploitation allows an attacker to upload arbitrary files to the server, which can subsequently be used to achieve remote code execution. This vulnerability affects all phpwcms versions up to and including 1.9.49 and 1.12.3. Users are advised to upgrade to version 1.9.50 or 1.12.4 to remediate this vulnerability.

## Impact

Successful exploitation of CVE-2026-110025 results in a complete compromise of the web application. Attackers can upload web shells or other malicious scripts to the server filesystem, leading to unauthorized code execution, data exfiltration, and potential lateral movement within the network. This impacts the confidentiality, integrity, and availability of the affected host.

## Recommendation

- Patch phpwcms to version 1.9.50 or 1.12.4 immediately.
- Audit the 'include/inc_front/content/' directory for any unauthorized or unknown file types or recent modifications.
- Implement strict ingress filtering for the web server to block suspicious file extensions (e.g., .php, .phtml, .php5) uploaded to document root directories.
