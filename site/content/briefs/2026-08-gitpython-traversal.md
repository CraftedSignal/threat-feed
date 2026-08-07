---
title: Path Traversal in GitPython via Malicious Submodule Names
slug: 2026-08-gitpython-traversal
description: GitPython fails to validate submodule names defined in .gitmodules files, allowing attackers to perform path traversal and create arbitrary Git repositories outside the intended working tree during submodule initialization.
date: "2026-08-07T21:31:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:17.10:*:*:*:*:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:lts:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_desktop:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server_eus:7.5:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_workstation:7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*
  - cpe:2.3:a:git-scm:git:2.17.0:*:*:*:*:*:*:*
  - cpe:2.3:a:gitforwindows:git:*:*:*:*:*:*:*:*
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows for the creation of a full Git repository at an attacker-chosen filesystem path, which can include malicious hooks.
    confidence_band: med
cves:
  - id: CVE-2018-11235
    cvss: 7.8
    epss: 0.48752
references:
  - https://github.com/advisories/GHSA-hmq2-w58f-27jc
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for systems utilizing GitPython for repository operations
      owner: IT Operations
      due: 48h
      evidence: GitPython is widely used in CI pipelines and automated tooling.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitPython to the latest patched version
      owner: IT Operations
      addresses: Affected GitPython versions <= 3.1.57
      evidence: Source advisory recommends version updates.
---

GitPython is vulnerable to a path traversal flaw (CWE-22) when initializing submodules. The library's `sm_name()` function, which extracts the name of a submodule from the `.gitmodules` file, performs no validation on the returned string. When `submodule_update(init=True)` is called, the library constructs an absolute path for the submodule's separate Git directory by joining the target directory with the unvalidated submodule name. 

An attacker can craft a malicious Git repository containing a `.gitmodules` file with a submodule name consisting of directory traversal sequences (e.g., `../../../../path/to/target`). When a victim clones this repository and initializes the submodules using GitPython, the library creates a new, fully initialized Git repository at the attacker-specified path. This vulnerability affects GitPython versions up to and including 3.1.57. This vulnerability is significant because it mirrors a class of attacks historically patched in the core Git CLI (CVE-2018-11235), and it poses a high risk to automated systems such as CI/CD pipelines, IDEs, and dependency managers that automatically clone and initialize submodules using GitPython.

## Attack Chain

1. Attacker creates a malicious Git repository and modifies the `.gitmodules` file.
2. Attacker sets the `[submodule "..."]` header name to include traversal sequences (e.g., `../../../../tmp/malicious_dir`).
3. Attacker hosts the repository on a platform accessible to the victim.
4. Victim executes a process that uses GitPython to clone the repository (e.g., `git.Repo.clone_from()`).
5. The application calls `sm.update(init=True)` or `repo.submodules` on the cloned repository.
6. GitPython parses the malicious `.gitmodules` name field without validation.
7. GitPython joins the unsafe name to the base directory path using `os.path.join`.
8. GitPython executes a command or file operation to create a new Git repository at the traversal-escaped path.

## Impact

Successful exploitation allows for the creation of arbitrary directories and Git repositories on the victim's filesystem, limited only by the privileges of the process running GitPython. This can lead to arbitrary file writes, potential overwriting of critical configuration files if the path is carefully chosen, and the introduction of malicious Git hooks or configurations at locations controlled by the attacker. Automated build environments are particularly susceptible due to the high volume of automated submodule initialization.

## Recommendation

* Update GitPython to a version where submodule name validation is implemented to prevent directory traversal.
* Restrict the privileges of service accounts executing GitPython clones, ensuring they operate with minimal filesystem permissions.
* Implement pre-processing logic to validate submodule names in `.gitmodules` files before passing them to GitPython, ensuring they do not contain path traversal characters.
* Audit CI/CD configurations to determine if GitPython is used for recursive submodule initialization and move to hardened environments where possible.
