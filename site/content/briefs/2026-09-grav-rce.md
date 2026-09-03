---
title: Remote Code Execution in Grav via Blueprint dynamicData
slug: 2026-09-grav-rce
description: An attacker with administrative page-editing permissions can achieve remote code execution in Grav versions prior to 2.0.7 by injecting arbitrary callables into page frontmatter, which are subsequently triggered by visitor requests.
date: "2026-09-02T18:04:09Z"
lastmod: "2026-09-03T00:04:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cms
  - web-vulnerability
  - authentication-bypass
  - 2fa
  - web-application-vulnerability
vendors:
  - Grav
products:
  - Grav (< 2.0.7)
  - Grav (< 2.0.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The PoC demonstrates execution of the 'id' command via a system call triggered through the application frontmatter processing.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated visitors to trigger the execution, crossing the trust boundary from page editing to RCE.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker who knows the victim's password can bypass TOTP-based 2FA by forcing a secret rotation during the pending-challenge window.
    confidence_band: high
cves:
  - id: CVE-2026-64850
    epss: 0.00343
references:
  - https://github.com/advisories/GHSA-fj2p-qj2f-74v5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64850
  - https://github.com/advisories/GHSA-7mgc-c7pq-3rr3
rules:
  - title: Detect Exploitation of CVE-2026-62669 - Unauthorized 2FA Secret Regeneration
    description: Detects unauthorized access to the Grav login regeneration task which is used to bypass 2FA.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Grav CMS to version 2.0.7 or later
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies 2.0.7 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Grav 2.0.7
      owner: IT Operations
      addresses: CVE-2026-64850
      evidence: Source advises upgrading to v2.0.7 to remediate Blueprint::dynamicData() vulnerability.
updates:
  - at: "2026-09-03T00:04:04Z"
    level: L1
    summary: 'added detection rule: Detect Exploitation of CVE-2026-62669 - Unauthorized 2FA Secret Regeneration'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7mgc-c7pq-3rr3
---

Grav CMS versions prior to 2.0.7 are susceptible to a remote code execution (RCE) vulnerability identified as CVE-2026-64850. The vulnerability stems from the `Blueprint::dynamicData()` method, which performs insufficient validation on class method inputs. Specifically, the application uses `call_user_func_array()` with input derived from page frontmatter without implementing an allowlist. 

An attacker with `admin.pages` or `api.pages.write` permissions can craft a malicious page configuration that designates `Grav\Common\Utils::arrayFilterRecursive` as a callable to execute system-level commands. Because the frontmatter is processed when a page is rendered, the payload executes with the privileges of the web-server user whenever a visitor (including unauthenticated users) requests the page. This vulnerability effectively escalates a compromise of administrative page-editing rights to full system-level code execution on the underlying server.

## Attack Chain

1. Attacker obtains valid `admin.pages` or `api.pages.write` permissions, likely via compromised administrative credentials.
2. Attacker logs into the Grav administrative interface and navigates to the page creation or editing module.
3. Attacker crafts a custom page containing malicious YAML frontmatter, specifically targeting the form plugin's field definitions.
4. Attacker inserts a `data-opts@` directive into the frontmatter, pointing to `Grav\Common\Utils::arrayFilterRecursive` as the callable.
5. Attacker embeds the target system command (e.g., `id`) within the frontmatter payload, passing it as the primary argument to the function.
6. Attacker saves the page configuration to the Grav CMS data store.
7. Attacker (or any subsequent visitor) triggers a GET request to the path corresponding to the malicious page.
8. Grav CMS processes the page frontmatter, invokes the malicious callable via `dynamicData()`, and executes the command on the web server.

## Impact

Successful exploitation results in arbitrary remote code execution on the host server under the context of the web-server user (e.g., `www-data` or `apache`). This allows for full system control, potential data exfiltration, or lateral movement within the hosting environment. Any user with page-editing privileges can turn a legitimate site into a persistent execution platform that triggers malicious commands upon every page view.

## Recommendation

1. Upgrade all Grav CMS installations to version 2.0.7 or later to address the insecure `call_user_func_array` invocation in `Blueprint.php`.
2. Audit current administrative accounts for `admin.pages` or `api.pages.write` permissions to ensure they are restricted to authorized personnel only.
3. Implement monitoring for POST requests to the Grav admin interface followed by anomalous GET requests to newly created or modified pages that may indicate payload testing.
4. Review system-level web server logs for suspicious process execution (e.g., `id`, `whoami`, `curl`, `wget`) originating from the web server process user.
