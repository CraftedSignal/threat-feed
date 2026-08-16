---
title: Arbitrary File Deletion in Podlove Podcast Publisher Plugin for WordPress
slug: 2026-08-podlove-arbitrary-file-deletion
description: Authenticated attackers can exploit a path traversal vulnerability in the Podlove Podcast Publisher plugin to delete arbitrary system files, potentially achieving remote code execution via POP chain or wp-config.php removal.
date: "2026-08-16T06:24:50Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Podlove
products:
  - Podlove Podcast Publisher
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability can be escalated to remote code execution by deleting critical files like wp-config.php or by utilizing a POP chain.
    confidence_band: high
cves:
  - id: CVE-2026-16099
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16099
---

The Podlove Podcast Publisher plugin for WordPress (versions 4.5.3 and earlier) contains a critical vulnerability due to insufficient file path validation within the 'create_link_item' function. Authenticated users with contributor-level privileges or higher can leverage this flaw to delete arbitrary files on the web server. This capability poses a significant risk to site integrity and availability, as attackers can delete core WordPress configuration files like 'wp-config.php' to force a re-installation or trigger further exploit chains.

Furthermore, researchers identified a property-oriented programming (POP) chain within the 'Podlove\ImageCache\GenerationGuard' class. An attacker can supply serialized data that, when unserialized, populates the object's properties to invoke 'wp_delete_file()' on a target file of their choosing. This facilitates remote code execution (RCE) scenarios by removing specific application files that redirect execution flow or weaken security postures. Given the plugin's broad utility in podcast hosting, defenders should prioritize patching or disabling the plugin until version 4.5.4 or later is deployed.

## Impact

Successful exploitation allows for the deletion of arbitrary files on the underlying filesystem, provided the web server process has the necessary file system permissions. This can lead to a complete denial of service for the WordPress site, the destruction of critical configuration files, or facilitate RCE through the identified POP chain mechanism. Impacted organizations include any entities running affected versions of the Podlove Podcast Publisher plugin on WordPress infrastructure.

## Recommendation

- Upgrade the Podlove Podcast Publisher plugin to version 4.5.4 or later immediately to resolve the path validation flaw.
- Implement access control reviews to ensure contributor-level accounts are restricted appropriately, minimizing the potential impact of authenticated exploit vectors.
- Audit web server access logs for anomalous POST requests directed at plugin-specific API endpoints that handle file linking or management.
