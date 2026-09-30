---
title: Unauthenticated Directory Traversal in WordPress Product Designer App Plugin
slug: 2026-09-product-designer-app-traversal
description: The Product Designer App plugin for WordPress up to version 1.1.3 is vulnerable to directory traversal allowing unauthenticated file read due to insecurely implemented authentication using publicly exposed tokens.
date: "2026-09-30T10:34:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:product_designer_app:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
  - file-read
  - directory-traversal
vendors:
  - WordPress
products:
  - Product Designer App (<= 1.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information
    confidence_band: high
cves:
  - id: CVE-2026-75098
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75098
rules:
  - title: Detect CVE-2026-75098 Exploitation Attempt - Path Traversal in Product Designer App
    description: Detects HTTP requests targeting the Product Designer App with directory traversal sequences in the svg parameter
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block requests with directory traversal patterns targeting the plugin
      owner: SOC
      due: 24h
      evidence: Plugin vulnerable to directory traversal via 'svg' parameter
  mitigation_plan:
    - priority: immediate
      action: Update Product Designer App to patched version when available
      owner: IT Operations
      addresses: CVE-2026-75098
      evidence: Source states all versions up to and including 1.1.3 are vulnerable
---

The Product Designer App plugin for WordPress, in all versions up to and including 1.1.3, contains a critical directory traversal vulnerability. Attackers can leverage this flaw to read arbitrary files from the underlying server filesystem. The plugin attempts to gate access to the vulnerable endpoint using a nonce and token mechanism; however, these values are rendered as global JavaScript variables on any page that utilizes the [pdapp-studio-page] shortcode. Because these credentials are publicly accessible to any anonymous visitor, the security control is effectively bypassed. This allows unauthenticated remote attackers to perform unauthorized file reads, potentially accessing sensitive configuration files, credentials, or system data. Defenders should prioritize updating the plugin to the latest patched version or removing the plugin if it cannot be immediately updated.

## Attack Chain

1. Attacker identifies a WordPress site running the Product Designer App plugin.
2. Attacker visits any page on the target site that renders the [pdapp-studio-page] shortcode.
3. Attacker parses the page source to extract the nonce and token values exposed as JavaScript global variables.
4. Attacker crafts a malicious HTTP request targeting the plugin endpoint, incorporating the harvested nonce and token for authentication.
5. Attacker injects directory traversal sequences (e.g., ../) into the 'svg' parameter of the request.
6. The plugin processes the input, failing to validate the path traversal, and returns the requested system file content in the HTTP response.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files on the web server. This can lead to the exposure of database credentials in wp-config.php, sensitive application environment variables, or private source code, facilitating full site compromise or lateral movement within the hosting environment.

## Recommendation

* Immediately update the Product Designer App plugin to a version later than 1.1.3 once a vendor patch is released.
* If no patch is available, disable or uninstall the plugin to eliminate the exposure of the vulnerable [pdapp-studio-page] shortcode.
* Implement web application firewall (WAF) rules to detect and block requests to the vulnerable plugin endpoint containing directory traversal sequences (e.g., ../, ..\/) in the 'svg' parameter.
* Audit access logs for high-frequency requests originating from single IPs targeting plugin-specific paths to identify potential automated scanning or exploitation attempts.
