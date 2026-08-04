---
title: Flowise Multiple Critical Vulnerabilities (RCE, Sandbox Escape, Broken Access Control)
slug: 2026-08-flowise-rce
description: Flowise 3.1.2 and earlier are affected by multiple critical vulnerabilities including unauthenticated RCE via environment-variable bypass, vm2 sandbox escape, and broken access control in the files API.
date: "2026-08-04T17:24:16Z"
lastmod: "2026-08-04T19:56:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
  - high
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:
tags:
  - rce
  - injection
  - flowise
  - flowiseai
  - sandbox-escape
  - broken-access-control
  - path-traversal
  - privilege-escalation
  - secrets-disclosure
  - authentication-bypass
  - cve-2025-8943
  - cve-2026-69263
  - cve-2026-69252
  - cve-2026-70478
  - cve-2026-70476
  - cve-2026-70475
  - cve-2022-24785
vendors:
  - FlowiseAI
products:
  - Flowise (3.1.2)
  - Flowise (<= 3.1.2)
  - Flowise Components (3.1.2)
  - nodevm (3.9.25)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The RCE payload leverages child_process.execSync to run arbitrary OS commands on the Flowise host, and the sandbox escape uses a reverse-shell payload executed by the Node.js process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The RCE script leverages child_process.execSync to run arbitrary OS commands on the Flowise host.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Once the chatflow is exposed via the public POST /api/v1/prediction/:id endpoint, any unauthenticated request triggers host RCE.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker could inject arbitrary code by inserting #";{malicious_code};// at the end of the AgentAsTool baseURL setting.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Any authenticated API key within the organization, even one with unrelated permissions, can list and delete files belonging to other workspaces.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker can supply a known or enumerated credential ID to an unauthenticated POST endpoint, forcing the application to perform an OAuth2 token refresh and return the new access token in the response body.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The executions endpoint lacks the checkAnyPermission() middleware, allowing any authenticated user to modify any execution record.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The server trusts the user-supplied subscriptionId and forwards it to the Stripe integration layer.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The server reads the stored refresh_token, exchanges it at the accessTokenUrl, and returns fresh token metadata.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The server decrypts the stored credential (containing clientId, clientSecret, refresh_token), sends a refresh request to the configured OAuth provider, and returns the new access_token in the response body.
    confidence_band: high
cves:
  - id: CVE-2025-8943
    cvss: 9.8
    epss: 0.7231
  - id: CVE-2026-69263
  - id: CVE-2026-69252
  - id: CVE-2026-70478
  - id: CVE-2026-70476
  - id: CVE-2026-70475
  - id: CVE-2026-70471
  - id: CVE-2022-24785
    cvss: 7.5
    epss: 0.0552
references:
  - https://github.com/advisories/GHSA-xc48-889x-5qmw
  - https://github.com/advisories/GHSA-4j8x-x6v7-w9rq
  - https://github.com/advisories/GHSA-qgvm-j2hm-6m38
  - https://github.com/advisories/GHSA-52fh-8v99-63c2
  - https://github.com/advisories/GHSA-gmmw-qg98-6j6p
  - https://github.com/advisories/GHSA-fm2f-4339-4p2f
  - https://github.com/advisories/GHSA-wch5-xp77-fxg4
  - https://github.com/advisories/GHSA-fr6g-7cq8-fg82
  - https://github.com/advisories/GHSA-88pr-878c-24wf
  - https://github.com/advisories/GHSA-8r8h-6vcc-xhrv
  - https://github.com/advisories/GHSA-wp74-f5hh-5f3r
  - https://github.com/advisories/GHSA-wg86-r78f-74mp
  - https://github.com/FlowiseAI/Flowise/pull/5701
  - https://github.com/FlowiseAI/Flowise/pull/5836
  - https://nvd.nist.gov/vuln/detail/CVE-2025-8943
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69263
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70476
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70475
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-70471
  - https://nvd.nist.gov/vuln/detail/CVE-2022-24785
rules:
  - title: Detect Suspicious Dynamic Import in Node.js via Pyodide
    description: Detects attempts to use dynamic import for child_process or fs modules, often associated with sandbox breakouts in Node.js environments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
  - title: Detect Unauthenticated OAuth2 Refresh Attempts
    description: Detects unauthorized attempts to access the Flowise OAuth2 credential refresh endpoint by monitoring for POST requests to the refresh path that may indicate exploitation of CVE-2026-70478.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-70476 Exploitation - Unauthorized Billing Modification
    description: Detects unauthorized attempts to modify billing or subscription plans via the organization API endpoints.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
  - title: Detect CVE-2026-70475 Exploitation - PUT Request to Flowise Executions
    description: Detects PUT requests to the executions endpoint which may indicate exploitation of CVE-2026-70475 by low-privileged users.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Unauthenticated OAuth2 Credential Refresh Attempts
    description: Detects potential exploitation of the unauthenticated OAuth2 token refresh endpoint in Flowise.
    platform: sigma
    severity: critical
    tactics:
      - collection
    techniques:
      - T1555.003
    data_sources:
      - webserver
  - title: Detect Excessive Data Exposure via Flowise API
    description: Detects potentially anomalous large response sizes from the Flowise upsert-history endpoint which may indicate data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1597
    data_sources:
      - webserver
  - title: Detects CVE-2026-69252 Exploitation - Unauthorized File Deletion in Flowise
    description: Detects DELETE requests to the /api/v1/files endpoint that target paths containing workspace identifiers outside of the user's expected scope.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 7
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
    - SOC
  immediate_actions:
    - action: Upgrade Flowise to the latest patched release immediately
      owner: IT Operations
      due: 24h
      evidence: Flowise (<= 3.1.2) is vulnerable to unauthenticated RCE and broken access control.
    - action: Review all active API keys and their assigned permissions in Flowise
      owner: SOC
      due: 24h
      evidence: CVE-2026-69252 allows any valid API key to perform unauthorized actions across workspaces.
  hunt_leads:
    - lead: Search logs for multiple successful DELETE requests to /api/v1/files from a single low-privileged API key.
      technique_id: T1078
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthorized file deletion identified in reproduction steps
  mitigation_plan:
    - priority: immediate
      action: Enable authentication for the Flowise instance if currently unauthenticated
      owner: IT Operations
      addresses: Unauthenticated API access
      evidence: On a default deployment with no authentication, any unauthenticated user who can reach the Flowise API can trigger RCE.
    - priority: immediate
      action: Restrict outbound network access for the Flowise server to prevent automatic installation of arbitrary npm/pip packages
      owner: IT Operations
      addresses: CVE-2026-69263 RCE chain
      evidence: The RCE chain relies on npx/npip installing attacker-controlled packages.
updates:
  - at: "2026-08-04T19:56:20Z"
    level: L2
    summary: merged Flowise sandbox-escape and broken-access-control advisories into a single canonical brief; normalized vendor/product names and removed incorrect CPEs
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wp74-f5hh-5f3r
      - https://github.com/advisories/GHSA-wg86-r78f-74mp
---

Flowise 3.1.2 and earlier are affected by multiple critical vulnerabilities. The most severe is an unauthenticated remote code execution flaw (CVE-2026-69263) that bypasses the CVE-2025-8943 patch through environment-variable injection. Additional issues include a vm2 sandbox escape (CVE-2022-24785) and a broken access control issue in the `/api/v1/files` endpoint (CVE-2026-69252). Because Flowise commonly runs unauthenticated and holds AI-provider API keys, successful exploitation typically leads to full host compromise and exposure of connected credentials.

## 1. Unauthenticated RCE via Environment Variable Bypass

Flowise (v3.1.2 and earlier) contains a critical flaw involving an incomplete environment variable blocklist, identified as CVE-2026-69263. The CVE-2025-8943 patch filtered dangerous CLI flags like `-y` for `npx`, but failed to account for `npm` configuration that can be passed via environment variables (e.g., `npm_config_yes`). A remote attacker can register a malicious MCP server with crafted environment variables, influencing the behavior of `npx`, `node`, or `python3` to achieve remote code execution.

### Attack Chain

1. Attacker discovers an internet-facing, unauthenticated Flowise instance.
2. Attacker creates or updates an MCP server configuration through the Flowise API.
3. Attacker crafts a JSON payload containing the `mcpServers` object with a command like `npx`.
4. Attacker inserts environment variables such as `npm_config_yes=true` into the `env` field of the payload.
5. Flowise validation logic (`validateCommandFlags`) is bypassed because the CLI flags are clean.
6. Flowise validation logic (`validateEnvironmentVariables`) is bypassed because the blocklist only contains four hardcoded entries (`PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `NODE_OPTIONS`).
7. Flowise spawns the `npx` process, which reads the injected environment variable and proceeds with automatic package installation.
8. Malicious code is executed under the privileges of the Flowise process, resulting in full system compromise.

## 2. vm2 Sandbox Escape to Remote Code Execution

Flowise uses the deprecated `patriksimek/vm2` library (via the `nodevm` module) to execute custom user-provided JavaScript. Components such as `AgentAsTool` invoke this sandbox with `useSandbox: false` or in insecure configurations. An injection point in the `baseURL` parameter of the `AgentAsTool` node allows an attacker to bypass `isValidURL` using a hash fragment, then chain a path traversal flaw in the `moment` library (CVE-2022-24785) to break out of the Node.js sandbox and execute arbitrary commands. This issue persists in Flowise 3.1.1 and impacts `nodevm` 3.9.25.

### Attack Chain

1. The attacker authenticates to the target Flowise instance and retrieves a valid organization ID and session cookies.
2. The attacker uploads a malicious JavaScript payload (e.g., a reverse shell) as a file to the application server.
3. The attacker configures an `AgentAsTool` or similar node within a Flowise workflow.
4. The attacker crafts a malicious `baseURL` input string containing a hash fragment injection, such as `#";\nfake = new String(".../tmp/rce.js"); ... //`.
5. The `AgentAsTool` component fails to sanitize the injected string and inserts it into the sandboxed execution context.
6. The `vm2` sandbox executes the injected code, which triggers the `moment.locale()` bypass to traverse the filesystem and access the uploaded payload.
7. The `child_process` module is invoked within the context of the Node.js process to execute the payload.
8. The attacker obtains a reverse shell or arbitrary code execution on the host system.

## 3. Broken Access Control in /api/v1/files

Flowise 3.1.2 and earlier contain a broken access control vulnerability (CVE-2026-69252) in the `/api/v1/files` endpoint. The application fails to verify workspace-level permissions, only checking for a general feature flag. Consequently, any authenticated API key - regardless of assigned role - can list and delete files stored in any workspace belonging to the same organization.

### Attack Chain

1. Attacker creates or obtains an API key with minimal permissions (e.g., `tools:view`) via legitimate account access.
2. Attacker inspects the `/api/v1/files` endpoint to identify accessible file paths.
3. Attacker sends a `GET` request to `/api/v1/files` using their low-privileged `Authorization: Bearer` token.
4. The application logic fails to check `activeWorkspaceId`, returning a list of all files across the entire organization.
5. Attacker parses the JSON response to extract paths belonging to target workspaces.
6. Attacker sends a `DELETE` request to `/api/v1/files` with the `path` parameter set to a file located in a foreign workspace.
7. The application performs the deletion using the organization ID context, successfully removing the unauthorized file.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated or authenticated attackers to execute arbitrary commands on the Flowise host, access or refresh OAuth credentials, and tamper with files across workspaces. Given that Flowise manages AI agents and sensitive API keys, compromise often leads to data exfiltration, lateral movement, and unauthorized access to connected third-party SaaS services.

## Recommendation

1. Upgrade Flowise to a version that patches CVE-2026-69263, CVE-2026-69252, and removes use of the deprecated `vm2` sandbox.
2. Implement strict authentication on all Flowise API endpoints; do not expose Flowise to the internet without authentication.
3. Restrict outbound network access for the Flowise server to prevent automatic installation of arbitrary npm/pip packages.
4. Audit all code paths utilizing `useSandbox: false` in Flowise components and transition them to secure isolation mechanisms such as E2B.
5. Implement strict input validation for URL fields, ensuring that hash fragments and newline characters are sanitized before dynamic code generation.
6. Review all active API keys and their assigned permissions; enforce least-privilege access per workspace.
7. Monitor the `/api/v1/files`, `/api/v1/prediction/:id`, OAuth refresh, and executions endpoints for anomalous requests.
