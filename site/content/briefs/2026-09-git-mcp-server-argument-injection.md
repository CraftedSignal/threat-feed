---
title: Argument Injection Vulnerability in git-mcp-server
slug: 2026-09-git-mcp-server-argument-injection
description: git-mcp-server version 2.15.1 is vulnerable to argument injection due to insufficient input validation in the ref and object parameters of its git tools, allowing for arbitrary file writes.
date: "2026-09-04T15:28:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:git-mcp-server:git-mcp-server:2.15.1:*:*:*:*:*:*:*
products:
  - git-mcp-server (2.15.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject git command-line options like --output= to write files outside the repository.
    confidence_band: high
cves:
  - id: CVE-2026-85626
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85626
rules:
  - title: Detect Suspicious Git Command Line Arguments
    description: Detects potential exploitation of CVE-2026-85626 by identifying git processes spawned with high-risk output arguments
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review environment for git-mcp-server version 2.15.1
      owner: IT Operations
      due: 24h
      evidence: Source identification of vulnerable version
  enrichment_needed:
    - item: Patched version availability
      owner: CTI
      reason: Monitor vendor for update release to enable remediation
      evidence: N/A
  hunt_leads:
    - lead: Search for git processes with --output flag in command history
      technique_id: T1059.003
      data_needed:
        - Process creation events with command line
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows injection of --output flag
  mitigation_plan:
    - priority: immediate
      action: Restrict service account permissions to prevent writing to system directories
      owner: IT Operations
      addresses: CVE-2026-85626
      evidence: Vulnerability involves arbitrary file writes
---

git-mcp-server version 2.15.1 contains an argument injection vulnerability within the ref and object parameters used by the git_log, git_diff, and git_show tools. The vulnerability arises because these parameters lack proper validation to prevent the inclusion of leading dashes, which are interpreted as command-line flags by the underlying git binary. An attacker who can influence these parameters can inject arbitrary git command-line arguments, such as the --output option. By controlling the output path, an attacker can coerce the process into writing files to unauthorized locations on the filesystem, provided those paths are accessible by the service account running the git-mcp-server process. This vulnerability (CVE-2026-85626) poses a significant risk for unauthorized file creation or overwriting, potentially leading to remote code execution or privilege escalation if sensitive configuration files or startup scripts are targeted.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated or authenticated user with access to the MCP interface to perform arbitrary file writes. This can result in system compromise, data destruction, or the injection of malicious scripts that gain execution context under the user account running the git-mcp-server instance.

## Recommendation

- Upgrade to a version of git-mcp-server that addresses CVE-2026-85626, as no specific version is identified as patched in the current report, monitor vendor security advisories for the remediation release.
- Implement strict input validation on the backend for all ref and object parameters to ensure they do not start with a dash character.
- Run the git-mcp-server process with the least privilege necessary, restricting write access to the filesystem to only required directories.
- Monitor process execution logs for instances where git child processes are spawned with unexpected command-line arguments, specifically the --output parameter.
