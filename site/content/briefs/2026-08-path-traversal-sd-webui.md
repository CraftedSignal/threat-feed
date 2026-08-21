---
title: Path Traversal in Stable Diffusion WebUI
slug: 2026-08-path-traversal-sd-webui
description: A path traversal vulnerability in Stable Diffusion WebUI allows unauthorized file disclosure via symlink manipulation when IIB access control is active.
date: "2026-08-21T15:25:32Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Stability AI
products:
  - Stable Diffusion WebUI
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: A symlink placed inside a scanned directory therefore satisfies the containment comparison performed by is_path_trusted ... and FileResponse follows the link when serving the response, so a link created in an image directory and targeting a file such as /etc/passwd discloses that file.
    confidence_band: high
cves:
  - id: CVE-2026-77815
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77815
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Stable Diffusion WebUI instance to remediate CVE-2026-77815
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-77815 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict symlink creation in directories processed by IIB extension
      owner: IT Operations
      addresses: CVE-2026-77815
      evidence: Source describes vulnerability as reliance on symlink containment failure
---

CVE-2026-77815 affects the Image-to-Image Browser (IIB) extension within Stable Diffusion WebUI. The vulnerability resides in the `to_abs_path` function located in `scripts/iib/tool.py`, which utilizes `os.path.normpath` to normalize file paths. Because `os.path.normpath` does not resolve symbolic links, the path validation logic (`is_path_trusted`) can be bypassed. An attacker who can influence the filesystem by creating a symbolic link within a scanned directory can point that link to sensitive files outside the intended root. If the IIB access control feature is enabled - either manually via the `IIB_ACCESS_CONTROL` environment variable or automatically when the WebUI is launched with network-exposing arguments like `--share` or `--listen` - the `FileResponse` function will follow the symlink and serve the contents of the target file, such as `/etc/passwd`, to the requester.

## Impact

Successful exploitation results in arbitrary local file disclosure of any file readable by the user process running the Stable Diffusion WebUI. This poses a significant risk for server-side information disclosure, potentially exposing configuration files, credentials, or system sensitive data in exposed WebUI deployments.

## Recommendation

1. Update the Stable Diffusion WebUI and the Image-to-Image Browser (IIB) extension to the latest version where `os.path.realpath` has replaced `os.path.normpath` for path resolution.
2. For deployments where the update is not immediately feasible, ensure `IIB_ACCESS_CONTROL` is set to 'disable' only if the deployment is fully isolated and does not require file path confinement, or conversely, restrict filesystem write access to the directories scanned by the extension.
3. Audit the filesystem for unauthorized symbolic links within the directories monitored by the IIB extension.
