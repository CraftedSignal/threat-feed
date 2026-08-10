---
title: 'CVE-2026-53787: Unauthenticated Arbitrary File Upload in Amasty Order Attributes for Magento 2'
slug: 2026-06-amasty-magento-file-upload
description: An unauthenticated arbitrary file upload vulnerability in Amasty Order Attributes for Magento 2 (versions before 4.0.0) allows attackers to upload files of any type to the store's media directory, which can lead to remote code execution (RCE) on misconfigured servers by uploading PHP files, enable malware hosting, facilitate stored cross-site scripting (XSS) via HTML/SVG uploads, or achieve path traversal to write files outside the intended directory.
date: "2026-06-14T21:19:57Z"
lastmod: "2026-08-10T02:36:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=14453898-58EA-59FC-B0F2-1A4092A77789&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - file-upload
  - magento
  - amasty
  - rce
  - xss
vendors:
  - Amasty
  - Adobe
products:
  - Order Attributes for Magento 2 (versions before 4.0.0)
  - Order Attributes (< 4.0.0)
  - Magento
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1609
    technique_name: Server Software Component
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-53787
    cvss: 9.8
    epss: 0.05216
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53787
  - https://sploitus.com/exploit?id=14453898-58EA-59FC-B0F2-1A4092A77789&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=14453898-58EA-59FC-B0F2-1A4092A77789
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-53787 Exploitation - Unauthenticated PHP Upload to Amasty Module
    description: Detects CVE-2026-53787 exploitation — HTTP POST requests to the Amasty Order Attributes upload endpoint containing a PHP file extension, indicating an attempt to upload a malicious file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1609
    data_sources:
      - webserver
  - title: Detects Access to Malicious Files in Amasty Upload Directory
    description: Detects HTTP GET/POST requests targeting PHP files or suspicious web configuration files within the Amasty Order Attributes media upload directory, potentially indicating post-exploitation activity after an arbitrary file upload via CVE-2026-53787.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-08-10T02:36:06Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=14453898-58EA-59FC-B0F2-1A4092A77789&utm_source=rss&utm_medium=rss
---

A critical unauthenticated arbitrary file upload vulnerability, tracked as CVE-2026-53787, exists in the Amasty Order Attributes extension for Magento 2 in all versions prior to 4.0.0. This flaw permits unauthenticated attackers to write arbitrary files to the store's media directory by submitting files of any type or name to a specific upload endpoint without authentication, session validation, or cart context. This vulnerability poses a significant risk to affected Magento 2 installations, enabling threat actors to achieve remote code execution (RCE) on systems where the media directory is configured to execute PHP files. Beyond RCE, attackers can also leverage this vulnerability for malware hosting, stored cross-site scripting (XSS) through malicious HTML or SVG file uploads, and path traversal to place files in unintended locations. The broad impact and ease of exploitation make this a high-priority threat for organizations utilizing the vulnerable Amasty extension.

## Attack Chain

1.  **Initial Access**: An unauthenticated attacker sends a crafted HTTP POST request to the `/media/amasty_order_attributes/upload` endpoint on a vulnerable Magento 2 instance.
2.  **Exploitation (Arbitrary File Upload)**: The attacker includes a malicious file, such as a PHP webshell (e.g., `shell.php` or `image.php.txt`), within the POST request. The vulnerable endpoint processes this request without requiring any form of authentication, session validation, or cart context.
3.  **Persistence (File Write)**: The Amasty Order Attributes component processes the request and writes the malicious file directly into the store's publicly accessible `media` directory. Attackers may also attempt path traversal techniques to write files to other arbitrary locations.
4.  **Execution (Webshell Access)**: The attacker subsequently sends a direct HTTP GET request to the URL of the uploaded PHP webshell (e.g., `https://[magento-site]/media/amasty_order_attributes/shell.php`).
5.  **Impact (Remote Code Execution)**: If the web server is configured to execute PHP files within the `media` directory, the malicious webshell is executed, granting the attacker remote code execution capabilities on the underlying server.
6.  **Alternative Impacts**: Depending on the uploaded file type, attackers could achieve stored cross-site scripting (XSS) by uploading malicious HTML or SVG files, or host malware for distribution.

## Impact

Successful exploitation of CVE-2026-53787 can lead to severe consequences for affected Magento 2 stores. The primary impact is remote code execution, allowing attackers full control over the compromised server, potentially leading to data theft, defacement, or further network penetration. The vulnerability also enables malware hosting, serving malicious content directly from the victim's domain, and stored cross-site scripting (XSS) attacks that could compromise customer data or sessions. Given Magento's e-commerce nature, a compromise could expose sensitive customer information, payment card details, and lead to significant financial and reputational damage. The CVSS v3.1 base score of 9.8 reflects the critical nature of this vulnerability.

## Recommendation

*   Immediately patch Amasty Order Attributes for Magento 2 to version 4.0.0 or later to address CVE-2026-53787.
*   Deploy the `Detects CVE-2026-53787 Exploitation - Unauthenticated PHP Upload to Amasty Module` Sigma rule to detect attempts to upload malicious files via the vulnerable endpoint.
*   Deploy the `Detects Access to Malicious Files in Amasty Upload Directory` Sigma rule to identify post-exploitation attempts to access uploaded webshells or malicious files.
*   Review web server configurations to ensure that the `media` directory and other upload directories do not permit the execution of PHP or other server-side scripting languages.
*   Enable comprehensive webserver access logging and ensure logs are ingested into your SIEM for analysis to support the detection rules above.
