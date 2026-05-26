---
title: Dell PowerFlex Manager Directory Listing Vulnerability (CVE-2025-32749)
slug: 2026-05-dell-powerflex-directory-listing
description: Dell PowerFlex Manager versions 4.6.2 and earlier contain a directory listing vulnerability (CVE-2025-32749) that allows an unauthenticated remote attacker to expose sensitive information.
date: "2026-05-26T13:31:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:dell:powerflex_appliance_intelligent_catalog:*:*:*:*:*:*:*:*
  - cpe:2.3:a:dell:powerflex_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:dell:powerflex_rack:*:*:*:*:*:*:*:*
tags:
  - cve-2025-32749
  - information-disclosure
  - directory-listing
vendors:
  - Dell
products:
  - PowerFlex Appliance Intelligent Catalog
  - PowerFlex Manager
  - PowerFlex Rack
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2025-32749
    cvss: 5.3
    epss: 0.00016
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-32749
  - https://www.dell.com/support/kbdoc/en-us/000391392/dsa-2025-434-security-update-for-dell-powerflex-appliance-multiple-third-party-component-vulnerabilities
  - https://www.dell.com/support/kbdoc/en-us/000391568/dsa-2025-435-security-update-for-dell-powerflex-rack-multiple-third-party-component-vulnerabilities
rules:
  - title: Detect Potential Directory Listing Attempt via HTTP GET
    description: Detects potential directory listing attempts by looking for HTTP GET requests containing common directory traversal sequences. Start with CVE-2025-32749 detection.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Potential Directory Listing Attempt via HTTP OPTIONS
    description: Detects potential directory listing attempts by looking for HTTP OPTIONS requests, which can sometimes reveal server directory structure. Start with CVE-2025-32749 detection.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A directory listing vulnerability exists in Dell PowerFlex Manager versions 4.6.2 and earlier (CVE-2025-32749). This flaw allows an unauthenticated attacker with remote network access to potentially list directories and expose sensitive information. The vulnerability stems from incorrect default permissions (CWE-276) within the application. Successful exploitation could reveal configuration files, credentials, or other sensitive data, potentially aiding further malicious activities. Dell has released security updates to address this vulnerability.

## Attack Chain

1.  The unauthenticated attacker identifies a vulnerable Dell PowerFlex Manager instance exposed on the network.
2.  The attacker crafts a malicious HTTP request to a specific endpoint on the PowerFlex Manager server that is susceptible to directory listing.
3.  The server, due to incorrect default permissions, responds with a listing of files and directories accessible to the webserver user.
4.  The attacker analyzes the directory listing to identify potentially sensitive files, such as configuration files, log files, or backup files.
5.  The attacker constructs further HTTP requests to retrieve the contents of these sensitive files.
6.  The server, again due to insufficient access controls, serves the requested files to the attacker.
7.  The attacker extracts sensitive information from the exposed files, such as usernames, passwords, API keys, or internal network configurations.
8.  The attacker uses the gathered information to further compromise the PowerFlex Manager instance or other systems on the network.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive information, such as usernames, passwords, API keys, and internal network configurations. This information could be used by an attacker to gain unauthorized access to the PowerFlex Manager system, other systems on the network, or sensitive data stored within the PowerFlex environment. The vulnerability affects Dell PowerFlex Appliance Intelligent Catalog, PowerFlex Manager, and PowerFlex Rack products.

## Recommendation

*   Apply the security updates provided by Dell to patch CVE-2025-32749 on affected PowerFlex Manager, PowerFlex Appliance Intelligent Catalog, and PowerFlex Rack installations.
*   Deploy the Sigma rule "Detect Potential Directory Listing Attempt via HTTP GET" to identify suspicious HTTP requests indicative of directory listing attempts.
*   Review and restrict access permissions on the PowerFlex Manager server to prevent unauthorized access to sensitive files and directories.
*   Monitor web server logs for unusual HTTP requests and responses that could indicate directory traversal or information disclosure attempts.
