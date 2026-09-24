---
title: OpenC3 COSMOS Authenticated Remote Code Execution
slug: 2026-09-openc3-rce
description: Authenticated users can achieve arbitrary code execution in OpenC3 COSMOS by writing malicious payloads into user-writable configuration overlays that are subsequently rendered as code by the application.
date: "2026-09-23T19:56:36Z"
lastmod: "2026-09-24T01:57:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openc3:cosmos:*:*:*:*:*:*:*:*
tags:
  - rce
  - authenticated-rce
  - openc3
  - cosmos
  - xss
  - web-vulnerability
  - session-hijacking
vendors:
  - OpenC3
products:
  - COSMOS (5.1.0-7.2.1)
  - COSMOS (7.2.0)
  - '@openc3/vue-common (>= 5.0.6, <= 7.2.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user can write into targets_modified/ below the admin tier (the storage-upload endpoint exempts that area from the admin gate)
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: ConfigParser renders every file as ERB by default, a GENERIC_READ_CONVERSION / GENERIC_WRITE_CONVERSION block is evaluated as code
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: A file written to targets_modified/<TARGET>/cmd_tlm/ is overlaid by System.setup_targets and processed by PacketConfig in the decom/multi microservices
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The BUTTON widget eval()s the stored button text in the browser when the button is activated.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The payload runs in the COSMOS origin and can read localStorage.openc3Token, enabling session/account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-77602
    cvss: 9.9
references:
  - https://github.com/advisories/GHSA-jjq7-m736-w977
  - https://github.com/advisories/GHSA-gvf2-2rh5-mpgf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77394
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade COSMOS to 7.3.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source recommends treating the user-writable overlay as data and patching the vulnerability.
  hunt_leads:
    - lead: Search API logs for POST requests to /screen, /tables/generate, or /scripts endpoints.
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies these endpoints as vectors for file writing and code execution.
  mitigation_plan:
    - priority: immediate
      action: Restrict API access to verified admin accounts.
      owner: IT Operations
      addresses: CVE-2026-77602
      evidence: Vulnerability is reachable by authenticated users due to permissive authorization logic.
updates:
  - at: "2026-09-24T01:57:22Z"
    level: L2
    summary: added coverage for COSMOS (7.2.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gvf2-2rh5-mpgf
---

OpenC3 COSMOS contains a critical vulnerability (CVE-2026-77602) allowing authenticated remote code execution (RCE). The application processes configuration files from a user-writable overlay directory (`targets_modified/`) before the system-defined read-only `targets/` tree. Because the configuration subsystem treats these user-controlled files as templates and executable code, an attacker can leverage several API endpoints - including screen saving, table generation, and storage uploads - to place malicious files in the overlay. These files are then executed via ERB rendering, generic code conversion blocks, or direct inclusion by the script runner suite analysis.

The vulnerability affects versions 5.1.0 through 7.2.1. In the open-source edition, authorization checks fail to enforce permission strings, allowing any authenticated user to exploit the flaw. Successful exploitation results in arbitrary code execution as the `openc3` user within the `cmd-tlm-api` container or target-specific microservices, granting the attacker control over configuration, telemetry, and command data.

## Attack Chain

1. Attacker obtains valid authentication credentials for the COSMOS API.
2. Attacker interacts with the `/screen` endpoint or `storage_controller` to bypass admin-gated file writing checks.
3. Attacker crafts a malicious configuration file containing an ERB template or a `GENERIC_WRITE_CONVERSION` code block.
4. Attacker writes the malicious file into the `targets_modified/` directory via authorized API calls.
5. Attacker triggers the vulnerability by calling `tables#generate`, `tables#report`, or initiating a `script_view` operation.
6. COSMOS configuration parser reads the malicious file from `targets_modified/`.
7. The application engine executes the embedded Ruby or Python code within the `cmd-tlm-api` or script runner container.
8. Attacker gains persistent or immediate arbitrary code execution within the container environment.

## Impact

The vulnerability allows arbitrary code execution as the `openc3` user. Compromised containers hold Redis and bucket credentials and reside on the internal service network, enabling the attacker to manipulate telemetry, commands, and configurations. In default multi-user deployments, the API is exposed, and even in single-host deployments, the service is reachable via local network paths.

## Recommendation

Prioritize patching and restrict access to the affected endpoints.

* Upgrade to a version of OpenC3 COSMOS containing the fix (post-v7.2.1).
* Restrict access to API endpoints involved in configuration and script management, specifically `/screen`, `tables/`, and `scripts/`, to trusted administrative users.
* Audit the `targets_modified/` directory for any unexpected or suspicious file modifications.
* Monitor API access logs for anomalous POST requests to configuration-related endpoints originating from non-administrative service accounts.
