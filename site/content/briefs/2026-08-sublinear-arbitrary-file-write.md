---
title: Arbitrary File Write in sublinear-time-solver MCP Tools
slug: 2026-08-sublinear-arbitrary-file-write
description: An arbitrary file write vulnerability (CVE-2026-55609) in consciousness-explorer and sublinear-time-solver MCP tools allows path traversal via unconstrained file paths, leading to potential system compromise.
date: "2026-08-25T18:48:49Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - consciousness-explorer
  - sublinear-time-solver
  - sublinear
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An arbitrary file write vulnerability exists in the consciousness-explorer component of sublinear-time-solver due to improper input sanitization in the export_state and import_state MCP tools.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: Direct Volume Access
    evidence: The application fails to constrain file paths, allowing an attacker to perform path traversal and overwrite arbitrary files.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xc9g-j69q-37xw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55609
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade affected npm and rust packages to patched versions.
      owner: IT Operations
      due: 48h
      evidence: Patches provided in the security advisory.
  mitigation_plan:
    - priority: immediate
      action: Restrict MCP server exposure to trusted clients only.
      owner: Security Engineering
      addresses: CVE-2026-55609
      evidence: Source workaround recommendation.
---

The vulnerability (CVE-2026-55609) stems from improper input validation within the Model Context Protocol (MCP) tool implementations for the `consciousness-explorer` and `sublinear-time-solver` packages. Specifically, the `export_state`, `import_state`, `saveVectorToFile`, and `loadVectorFromFile` tools process user-supplied `filepath` arguments by passing them directly to Node.js `fs.writeFileSync` and `fs.readFileSync` calls without sanitization. 

This lack of path confinement enables path traversal attacks, where an attacker can supply sequences such as `../../` to escape the intended directory. Because the application processes these inputs with the privileges of the server user, an attacker can overwrite critical system files, including `~/.ssh/authorized_keys` or application binaries, facilitating privilege escalation or remote code execution. This affects `consciousness-explorer` prior to 1.1.2, `sublinear-time-solver` prior to 1.6.0, and the `sublinear` crate prior to 0.2.0.

## Impact

Successful exploitation results in arbitrary file write capabilities, compromising the integrity of the server host. This poses a significant risk if the MCP server is exposed to untrusted clients, as an attacker could gain control over the host environment by overwriting configuration files or injecting malicious scripts into execution paths.

## Recommendation

- Upgrade `consciousness-explorer` to 1.1.2 or later, `sublinear-time-solver` to 1.6.0 or later, and `sublinear` to 0.2.0 or later to apply the path-confinement and basename-only contract fixes.
- Implement the recommended environment variables `CONSCIOUSNESS_EXPLORER_STATE_DIR` and `SUBLINEAR_SOLVER_VECTOR_DIR` to enforce state file storage in dedicated, non-sensitive directories.
- Apply the principle of least privilege by running the MCP server under a dedicated, restricted-privilege user account.
- Audit logs for the `export_state` and `import_state` MCP tool calls to identify attempts to supply non-basename paths or path traversal sequences.
