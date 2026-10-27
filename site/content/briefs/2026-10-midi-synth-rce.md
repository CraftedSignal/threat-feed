---
brief_id: brief-2026-10-27-midi-synth-rce
event_id: brief-2026-10-27-midi-synth-rce
revision: 1
activity_at: "2026-10-27T18:15:53Z"
title: 'midi-Synth: Unauthenticated arbitrary file upload remote code execution (CVE-2026-1306)'
slug: 2026-10-midi-synth-rce
description: A critical unauthenticated arbitrary file upload vulnerability in the WordPress plugin midi-Synth (CVE-2026-1306) allows remote attackers to achieve full server compromise by uploading and executing arbitrary PHP files via the admin-ajax.php endpoint.
date: "2026-10-27T18:15:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation.
cpes:
  - cpe:2.3:a:midi-synth_project:midi-synth:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - arbitrary-file-upload
  - rce
  - web-application-vulnerability
products:
  - midi-Synth (< 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated arbitrary file upload in midi-Synth via export AJAX action leads to RCE.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: The --shell flag uploads a persistent backdoor to the target server.
    confidence_band: high
cves:
  - id: CVE-2026-1306
    cvss: 9.8
    epss: 0.04827
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1306
  - https://sploitus.com/exploit?id=97A4BB46-6450-5A5B-B0CF-4C0DEC06BA80
  - https://sploitus.com/exploit?id=97A4BB46-6450-5A5B-B0CF-4C0DEC06BA80&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-1306 exploitation - POST to admin-ajax.php with export action
    description: Detects potential exploitation attempts of CVE-2026-1306 by monitoring for POST requests to admin-ajax.php containing the export action and potentially malicious file extensions in the filename.
    platform: sigma
    severity: critical
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
    - action: Inventory all WordPress instances and check if the midi-Synth plugin is installed.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-1306 affects midi-Synth plugin.
    - action: Upgrade midi-Synth plugin to version 2.0.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 2.0.0 contains the patch.
  hunt_leads:
    - lead: Search web access logs for successful POST requests to admin-ajax.php containing 'action=export'.
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit uses POST to admin-ajax.php with action=export.
  mitigation_plan:
    - priority: immediate
      action: Upgrade midi-Synth to 2.0.0.
      owner: IT Operations
      addresses: CVE-2026-1306
      evidence: Source states patch is in version 2.0.0.
---

The midi-Synth WordPress plugin contains a critical unauthenticated arbitrary file upload vulnerability (CVE-2026-1306) in the export AJAX handler of admin-ajax.php. The plugin fails to validate file extensions, MIME types, or file content, allowing unauthenticated users to upload malicious files to the /wp-content/plugins/midi-synth/sound/ directory. Because this directory is web-accessible and allows PHP execution, an attacker can achieve remote code execution (RCE). The vulnerability is remediated in version 2.0.0.

## Attack Chain
1. Attacker performs a GET request to the WordPress homepage.
2. Attacker parses the HTML response to extract the hardcoded nonce (`midiSynth_nonce`) embedded in frontend JavaScript.
3. Attacker sends a POST request to /wp-admin/admin-ajax.php with action=export and the extracted nonce.
4. Attacker includes the filename (e.g., shell.php) and base64-encoded file content in the POST parameters.
5. The plugin decodes and writes the file to the web-accessible /wp-content/plugins/midi-synth/sound/ directory.
6. Attacker requests the newly uploaded PHP file via the browser to trigger code execution.

## Impact
Successful exploitation allows for full server compromise, including loss of confidentiality, integrity, and availability of the affected WordPress site.

## Recommendation
- Update the midi-Synth plugin to version 2.0.0 or later immediately.
- If updates cannot be applied, deactivate and remove the plugin from the environment.
- Audit the /wp-content/plugins/midi-synth/sound/ directory for unexpected files and remove any malicious entries.
- Implement a WAF rule to block POST requests to admin-ajax.php where action=export and the fileName parameter ends in .php.
- Review server access logs for anomalous POST requests to admin-ajax.php as defined in the hunt leads.
