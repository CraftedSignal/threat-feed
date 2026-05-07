---
title: vm2 NodeVM require.root Bypass via Symlink Traversal
slug: 2024-01-03-vm2-symlink-bypass
description: A vulnerability exists in vm2 version 3.10.5 where NodeVM's `require.root` path restriction can be bypassed using filesystem symlinks, allowing sandboxed code to load modules from outside the allowed root directory in host context, leading to remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - remote-code-execution
  - symlink
vendors:
  - npm
products:
  - vm2 (3.10.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-cp6g-6699-wx9c
rules:
  - title: vm2 Sandbox Escape via Suspicious Host Require
    description: Detects potential vm2 sandbox escapes by monitoring for require calls that load modules from outside the defined root path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: vm2 Sandbox Escape Attempt via Process Spawn
    description: Detects potential exploitation attempts by monitoring for process spawns initiated by vm2 with host context.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The vm2 library, a popular Node.js sandbox, is vulnerable to a symlink bypass in version 3.10.5. This flaw allows sandboxed code to escape the intended restrictions imposed by the `require.root` option. The vulnerability arises because the path validation performed by `isPathAllowed` uses `path.resolve()`, which does not dereference symlinks. In contrast, Node.js's native `require()` function, used for module loading, does follow symlinks. This discrepancy allows an attacker to create a symlink within the allowed root directory that points to a location outside the root, effectively bypassing the sandbox and enabling the loading of arbitrary host-realm modules. This can lead to remote code execution on the host system. The presence of symlinks is common in environments using pnpm, npm workspaces, or npm link.

## Attack Chain

1. Host application creates a `NodeVM` instance with `require.root` set to a specific directory (e.g., `/tmp/root`) and `require.context` set to `host`.
2. A symlink is created within the `require.root` directory (e.g., `/tmp/root/node_modules/safe`) that points to a location outside the root directory (e.g., `/outside/root/vm2/`). This symlink can be created using tools like pnpm or npm link.
3. Sandboxed code within the `NodeVM` calls `require('safe')`, intending to load a module from within the allowed root.
4. The `DefaultResolver.resolveFull()` function resolves the module path to `/tmp/root/node_modules/safe/index.js`.
5. The `isPathAllowed()` function checks if the resolved path starts with the `require.root` directory, which passes because the symlink is not yet resolved.
6. The `loadJS()` function detects that `context` is set to `host` and calls `this.hostRequire(filename)`.
7. Node.js's native `require()` function follows the symlink, loading the module from the actual location outside the root directory, `/outside/root/vm2/index.js`.
8. The module from outside the intended sandbox is executed in the host realm, potentially granting the attacker the ability to execute arbitrary commands on the host system.

## Impact

Successful exploitation allows untrusted sandboxed code to escape the vm2 sandbox, achieving remote code execution on the host system. An attacker can bypass the `require.root` restriction, a primary defense mechanism, and load arbitrary modules from the host realm. This is particularly impactful in environments that use pnpm, npm workspaces, or `npm link`, as these tools frequently create symlinks, making the vulnerability more readily exploitable. The vulnerability can lead to complete compromise of the host system.

## Recommendation

*   Apply the recommended remediation by dereferencing symlinks with `fs.realpathSync` before path validation in `lib/filesystem.js` and `lib/resolver-compat.js` as outlined in the advisory to prevent the bypass.
*   Deploy the "vm2 Sandbox Escape via Suspicious Host Require" Sigma rule to detect attempts to load modules from outside the intended sandbox via symlinks.
*   Upgrade to a patched version of vm2 that includes the fix for CVE-2026-43998.
