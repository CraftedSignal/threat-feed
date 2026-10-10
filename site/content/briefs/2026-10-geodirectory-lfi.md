---
title: Unauthenticated Local File Inclusion in GeoDirectory WordPress Plugin
slug: 2026-10-geodirectory-lfi
description: The GeoDirectory plugin for WordPress is vulnerable to unauthenticated local file inclusion (LFI) via the design_type parameter, allowing remote attackers to execute arbitrary PHP code.
date: "2026-10-10T07:51:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ayecode:geodirectory:*:*:*:*:*:wordpress:*:*
tags:
  - lfi
  - wordpress
  - web-application-vulnerability
vendors:
  - Ayecode
products:
  - GeoDirectory – WP Business Directory Plugin and Classified Listings Directory (<= 2.8.187)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This makes it possible for unauthenticated attackers to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-104899
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104899
rules:
  - title: Detect CVE-2026-104899 Exploitation - Unauthenticated LFI via GeoDirectory Plugin
    description: Detects exploitation attempts against CVE-2026-104899 where an unauthenticated actor sends a request to the server with a malicious path in the design_type parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to block exploitation of CVE-2026-104899
      owner: SOC
      due: 24h
      evidence: Source confirms CVE-2026-104899 LFI vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GeoDirectory plugin to a version higher than 2.8.187
      owner: IT Operations
      addresses: CVE-2026-104899
      evidence: Source states all versions up to and including 2.8.187 are affected.
---

The GeoDirectory - WP Business Directory Plugin and Classified Listings Directory plugin for WordPress is affected by a critical Local File Inclusion (LFI) vulnerability identified as CVE-2026-104899. This vulnerability exists in all versions up to and including 2.8.187. The flaw originates from the improper validation of the 'design_type' parameter, which allows unauthenticated attackers to supply arbitrary file paths for inclusion. 

Defenders should note that the exploit is made trivial by the predictable nature of the required security nonce. The plugin exposes the 'geodir_basic_nonce' via the 'geodir_params' script object on all public frontend pages, allowing any anonymous visitor to retrieve the token necessary to bypass security checks. Successful exploitation enables attackers to include and execute arbitrary .php files, potentially leading to full server compromise, data exfiltration, and unauthorized access to site databases. This represents a significant risk to any WordPress environment utilizing the affected plugin version.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary PHP code on the underlying web server. This can lead to complete site takeover, persistent backdoor installation, exfiltration of sensitive site configuration data (such as database credentials in wp-config.php), and further lateral movement within the hosting infrastructure.

## Recommendation

Prioritized actions for security teams:
- Update the GeoDirectory - WP Business Directory Plugin and Classified Listings Directory to a patched version beyond 2.8.187 immediately.
- Audit web server access logs for anomalous GET or POST requests directed at the WordPress site containing the 'design_type' parameter with file path strings or directory traversal sequences.
- Implement a Web Application Firewall (WAF) rule to block requests containing directory traversal sequences or suspicious file path references in the 'design_type' parameter.
