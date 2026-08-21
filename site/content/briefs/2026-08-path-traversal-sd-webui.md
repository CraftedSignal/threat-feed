---
title: Path Traversal in Stable Diffusion WebUI
slug: 2026-08-path-traversal-sd-webui
description: CVE-2026-77814 is a path traversal vulnerability in Stable Diffusion WebUI caused by improper prefix validation in the is_path_trusted function, enabling unauthorized file access in network-exposed deployments.
date: "2026-08-21T15:25:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Stable Diffusion
products:
  - Stable Diffusion WebUI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw is present in network-exposed deployments, allowing unauthenticated attackers to disclose files the confinement was meant to exclude.
    confidence_band: high
cves:
  - id: CVE-2026-77814
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77814
rules:
  - title: Detects CVE-2026-77814 Exploitation - Path Traversal Attempt
    description: Detects potential path traversal attempts targeting Stable Diffusion WebUI by looking for directory traversal sequences or suspicious path suffixes in HTTP requests.
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Review exposed WebUI deployments and apply vendor patches for CVE-2026-77814.
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure.
    - action: Deploy Sigma rule to webserver logs to monitor for path traversal attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Source describes path-based access control bypass.
  hunt_leads:
    - lead: Search web logs for successful HTTP 200 responses to paths containing '_private' subdirectories.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The flaw allows accessing files the confinement was meant to exclude.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the WebUI via firewall rules.
      owner: IT Operations
      addresses: CVE-2026-77814
      evidence: Confinement is active in the network-exposed WebUI deployments.
---

CVE-2026-77814 is a path traversal vulnerability residing in the `scripts/iib/api.py` file of the Stable Diffusion WebUI. The vulnerability stems from an insecure implementation of the `is_path_trusted` function, which performs a prefix check using `path.startswith(parent_path)` without appending a path separator. Consequently, if `/data/images` is the intended authorized directory, an attacker can bypass this restriction by requesting a path that starts with the same string, such as `/data/images_private/secret.txt`. 

The security control is governed by `get_enable_access_control` in `scripts/iib/tool.py`. It is active when `IIB_ACCESS_CONTROL` is set to 'enable', or when the WebUI is exposed via `--share`, `--ngrok`, `--listen`, or `--server_name` flags. Deployments using these network-exposure options are vulnerable to unauthorized file disclosure. This flaw is critical for defenders because it allows attackers to bypass intended file system confinement to retrieve sensitive configuration or system files.

## Impact

Successful exploitation allows unauthenticated remote attackers to perform path traversal and access files outside of the intended web root. This leads to the disclosure of sensitive data, such as system configuration files or other private assets reachable by the user account running the WebUI service. The risk is elevated in shared or network-exposed environments where the WebUI is intentionally configured to listen on external interfaces.

## Recommendation

- Upgrade Stable Diffusion WebUI to a version that applies the fix, which uses `os.sep` to enforce directory boundaries during path validation.
- Until patched, restrict network access to the WebUI interface using a firewall or VPN to prevent exploitation of the path traversal logic in network-exposed deployments.
- Audit logs for HTTP requests containing directory traversal sequences or attempts to access directories that share a common prefix with authorized storage paths.
- Disable IIB_ACCESS_CONTROL if the functionality is not required or if the risk cannot be mitigated through network isolation.
