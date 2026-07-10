---
title: 'CVE-2026-15282: WordPress Instant Appointment Plugin Arbitrary File Upload to RCE'
slug: 2026-07-wordpress-insapp-rce
description: An unauthenticated attacker can exploit CVE-2026-15282, an arbitrary file upload vulnerability due to missing file type validation in the `insapp_upload_image_as_attachment` function of the WordPress Instant Appointment plugin up to version 1.2, to upload malicious files and achieve remote code execution on the affected server.
date: "2026-07-10T05:17:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - vulnerability
  - rce
  - file-upload
  - webserver
vendors:
  - tenteeglobal
  - WordPress
products:
  - Instant Appointment Plugin <= 1.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: ""
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-15282
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15282
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/097b1530-64fa-45b2-85f3-c6a2311405b5?source=cve
  - https://plugins.trac.wordpress.org/browser/instant-appointment/trunk/includes/ajax/ajax_services.php#L3
  - https://plugins.trac.wordpress.org/browser/instant-appointment/trunk/includes/front-end/ajax/login_ajax.php#L584
  - https://plugins.trac.wordpress.org/browser/instant-appointment/trunk/includes/front-end/ajax/login_ajax.php#L598
rules:
  - title: Detect WordPress Web Shell Access in Uploads Directory (CVE-2026-15282 Post-Exploitation)
    description: Detects attempts to execute PHP files within the WordPress uploads directory, often indicative of a successfully exploited arbitrary file upload vulnerability such as CVE-2026-15282 leading to web shell placement and execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-15282 identifies a critical arbitrary file upload vulnerability within the Instant Appointment plugin for WordPress, impacting all versions up to and including 1.2. The flaw stems from insufficient file type validation in the `insapp_upload_image_as_attachment` function. This oversight allows unauthenticated attackers to upload arbitrary files, including malicious scripts such as web shells, directly onto the affected web server. The consequence is severe, enabling remote code execution (RCE) and potentially complete compromise of the WordPress site and its underlying server. This vulnerability, if exploited, grants attackers full control, impacting data integrity, confidentiality, and availability. Organizations using this plugin should prioritize immediate patching or mitigation to prevent exploitation.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the vulnerable Instant Appointment plugin (versions <= 1.2).
2. The attacker crafts an HTTP POST request targeting an endpoint that utilizes the `insapp_upload_image_as_attachment` function (e.g., via `admin-ajax.php` or direct access to `ajax_services.php`/`login_ajax.php`).
3. The request includes a malicious file payload, such as a PHP web shell, camouflaged within the expected file upload parameters.
4. Due to the missing file type validation in the plugin's function, the server accepts and stores the malicious file in a publicly accessible directory (e.g., `/wp-content/uploads/`).
5. The attacker then sends a subsequent HTTP GET request to the URL of the newly uploaded malicious file.
6. Upon accessing the malicious file, the web server executes the PHP code, granting the attacker remote code execution capabilities on the underlying server.
7. With RCE, the attacker can establish persistence, exfiltrate data, deface the website, or pivot to other systems on the network.

## Impact

Successful exploitation of CVE-2026-15282 grants unauthenticated attackers remote code execution on the compromised WordPress server. This level of access allows for full control over the affected website and potentially the host system. Attackers can deface web pages, inject malicious content (e.g., for phishing or malware distribution), exfiltrate sensitive data from the database or server files, install backdoors, or use the compromised server as a pivot point for further attacks on the internal network. The high CVSS score of 9.8 reflects the critical nature and potential for complete system compromise without prior authentication.

## Recommendation

* Immediately update the Instant Appointment plugin for WordPress to a patched version beyond 1.2 to remediate CVE-2026-15282.
* Deploy the provided Sigma rule to your SIEM to detect post-exploitation web shell access related to arbitrary file uploads on your WordPress instances.
* Regularly review web server access logs for unusual requests to `/wp-content/uploads/` directories, specifically for executable file extensions such as `.php`, `.phtml`, or `.php5`.
* Implement file integrity monitoring on WordPress core, plugin, and theme directories to detect unauthorized file creations or modifications.
