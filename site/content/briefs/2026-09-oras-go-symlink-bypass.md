---
title: Arbitrary File Write in oras-go via Symlink-Chain Bypass
slug: 2026-09-oras-go-symlink-bypass
description: The oras-go library contains a path traversal vulnerability in its OCI layer extraction logic that allows attackers to overwrite arbitrary files on the host filesystem via a symlink-chain bypass.
date: "2026-09-17T19:11:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - path-traversal
  - library-vulnerability
  - supply-chain
vendors:
  - oras
products:
  - oras-go (<= 2.6.1)
affected_os:
  - linux
  - macos
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The result is arbitrary file create/overwrite outside the store's working directory under the default AllowPathTraversalOnWrite=false configuration — a canonical tar-slip → RCE primitive.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can overwrite arbitrary files on the host filesystem when a user extracts a malicious container image or layer.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security Engineering
  immediate_actions:
    - action: Audit CI/CD pipelines to identify instances of oras-go usage for image layer extraction.
      owner: DevOps
      due: 48h
      evidence: oras-go <= v2.6.1 is vulnerable to arbitrary file write.
  mitigation_plan:
    - priority: immediate
      action: Transition extraction processes to a high-privilege restricted environment if an immediate upgrade to the patched version is not possible.
      owner: IT Operations
      addresses: oras-go (<= 2.6.1)
      evidence: Vulnerability persists in default file.Store configuration.
---

The `content/file.Store` component in `oras-go` (versions `<= v2.6.1`) is vulnerable to an arbitrary file write attack during the extraction of OCI layer tarballs. The vulnerability is triggered when a descriptor includes the annotation `io.deis.oras.content.unpack: "true"`. The library performs lexical path validation using `filepath.Join` to ensure extracted files stay within the target extraction directory. However, this mechanism fails to account for kernel-level symlink resolution, where intermediate directory components may be symlinks that redirect subsequent path components.

An attacker can create a malicious OCI layer containing a symlink chain that lexically appears to reside within the extraction root but resolves to an arbitrary absolute path at the kernel level. A follow-up regular file entry with the same name is then opened without `O_NOFOLLOW` flags, allowing the attacker to write content through the symlink and overwrite files outside the intended working directory. This vulnerability provides an RCE primitive for users or automated systems that extract untrusted container images using affected `oras-go` versions.

## Attack Chain

1. The attacker prepares a malicious OCI layer tarball and publishes it to a registry, setting `io.deis.oras.content.unpack: "true"` in the layer's descriptor.
2. The victim invokes `oras.Copy` or a similar function to pull and unpack the malicious layer into a local directory using an affected `oras-go` version.
3. The extraction routine parses the tar headers, creating a sequence of nested directories that facilitate a deep path structure.
4. The library extracts a symlink entry named "up" that points back to the base extraction directory, which is validated lexically as compliant.
5. The library extracts an "escape" symlink whose target is crafted with `..` components to cross the "up" symlink and escape the extraction root at the kernel-resolution level.
6. The library extracts a regular file entry sharing the name "escape", triggering the `writeFile` logic.
7. The `writeFile` function opens the path using `os.OpenFile` without `O_NOFOLLOW`, causing the kernel to follow the symlink and perform the write operation at the attacker-controlled absolute path.
8. The final payload is written to the target location on the host, achieving arbitrary file overwrite.

## Impact

Successful exploitation allows attackers to overwrite critical system files, configuration files, or binaries on the host system where `oras-go` is used for image extraction. This can lead to local privilege escalation or arbitrary code execution. The scope includes any application or service relying on `oras-go` for OCI artifact processing.

## Recommendation

1. Upgrade `oras-go` to a version that addresses this vulnerability (post-v2.6.1) once a patch is available.
2. If patching is not immediately feasible, restrict the environment where untrusted images are unpacked to a sandboxed, low-privilege container or a dedicated filesystem namespace.
3. Implement post-extraction integrity checks to ensure critical system files have not been modified by the container runtime or image manipulation tools.
4. Monitor for unexpected file modifications in sensitive directories (e.g., `/etc/`, `/root/.ssh/`) originating from processes that utilize `oras-go`.
