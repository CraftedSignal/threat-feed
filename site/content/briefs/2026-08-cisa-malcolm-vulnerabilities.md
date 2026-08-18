---
title: Multiple Vulnerabilities in CISA Malcolm Network Analysis Suite
slug: 2026-08-cisa-malcolm-vulnerabilities
description: Multiple vulnerabilities in CISA Malcolm, including RCE, path traversal, and resource exhaustion, allow authenticated attackers to execute arbitrary code or cause denial-of-service.
date: "2026-08-18T17:49:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cisa
  - rce
  - dos
vendors:
  - CISA
products:
  - CISA Malcolm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated GET /server/php/files/.php then executes the uploaded code as www-data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: a user holding the upload-only role runs arbitrary PHP as www-data inside the file-upload container.
    confidence_band: high
cves:
  - id: CVE-2026-63133
    cvss: 6.5
    epss: 0.00249
  - id: CVE-2026-63134
    cvss: 5.4
    epss: 0.00249
  - id: CVE-2026-63177
    cvss: 7.1
    epss: 0.00178
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-230-01
  - https://github.com/cisagov/Malcolm/pull/1043
  - https://github.com/cisagov/Malcolm/pull/1026
rules:
  - title: Detect CVE-2026-55676 Exploitation Attempt
    description: Detects unauthorized attempts to upload or execute files through the CISA Malcolm file-upload component by monitoring for suspicious PHP file patterns in the upload directory.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CISA Malcolm, a network traffic analysis suite, contains several critical vulnerabilities that may lead to arbitrary code execution, denial-of-service, or authorization bypass. An authenticated attacker can exploit insecure file upload handling to upload and execute malicious PHP scripts within the file-upload container. Additional flaws include path traversal vulnerabilities in the archival processing component and resource exhaustion (denial-of-service) via uncontrolled file extraction. Furthermore, authorization bypass vulnerabilities exist in the Nginx OpenResty Lua layer due to path normalization discrepancies, potentially allowing unauthorized access to restricted backend services. These issues affect various versions of CISA Malcolm prior to 26.07.0. Organizations should patch to the latest version to mitigate these security risks. The impacted CVEs are CVE-2026-55676, CVE-2026-63133, CVE-2026-63134, CVE-2026-63177, CVE-2026-19670, and CVE-2026-19671.

## Impact

Successful exploitation of these vulnerabilities can lead to full compromise of the affected container via remote code execution (CVE-2026-55676) or persistent denial-of-service conditions (CVE-2026-63133). In environments where Malcolm is deployed for network monitoring, compromise may result in the exfiltration of sensitive captured traffic or unauthorized access to restricted control functions, impacting information technology infrastructure worldwide.

## Recommendation

* Update CISA Malcolm installations to version 26.07.0 or later to address CVE-2026-63133, CVE-2026-63134, and CVE-2026-63177.
* Update CISA Malcolm to version 26.06.1 or later to address CVE-2026-55676.
* Restrict access to the Malcolm dashboard and upload interfaces to trusted users only to mitigate the risk from the authentication/authorization-dependent vulnerabilities.
* Review web server logs for suspicious POST requests to /server/php/submit.php that might indicate file upload exploitation attempts.
