---
title: Use-After-Free Vulnerability in GNOME Mutter Wayland ICC Path
slug: 2026-10-mutter-uaf
description: A use-after-free vulnerability in the GNOME mutter compositor allows local attackers to trigger crashes or arbitrary code execution via a malicious Wayland client manipulating wp_image_description_v1 resources.
date: "2026-10-12T15:43:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnome:mutter:*:*:*:*:*:*:*:*
vendors:
  - GNOME
products:
  - mutter
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This can crash the GNOME session and may allow arbitrary code execution within the compositor process.
    confidence_band: high
cves:
  - id: CVE-2026-108094
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108094
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade mutter packages to the patched version as released by the Linux distribution vendor.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-108094 resolution requires software update.
  mitigation_plan:
    - priority: immediate
      action: Identify and restrict execution of unauthorized software that acts as a Wayland client on multi-user systems.
      owner: SOC
      addresses: CVE-2026-108094
      evidence: Exploitation requires a malicious Wayland client.
---

A high-severity use-after-free (UAF) vulnerability, tracked as CVE-2026-108094, exists in the GNOME mutter compositor. The flaw is located within the Wayland color-management ICC (International Color Consortium) image-description handling code. An attacker with local access can execute a malicious Wayland client to interact with the compositor. By specifically destroying a `wp_image_description_v1` resource at the precise moment an asynchronous ICC file read is in progress, the attacker causes the compositor to continue operations using a stale pointer to freed memory.

Upon the completion of the ICC file read, the compositor attempts to access the already freed `wl_resource`. This results in a memory corruption scenario where the compositor writes to or frees data based on invalid memory pointers. This vulnerability is significant because it allows a local, unprivileged user to destabilize the graphical session or potentially gain arbitrary code execution context within the compositor process, which often operates with elevated privileges in Linux desktop environments.

## Impact

The impact of this vulnerability is significant for multi-user Linux systems or environments where local users may be untrusted. Successful exploitation causes a complete crash of the GNOME session for the targeted user. In more critical scenarios, the memory corruption can be weaponized to achieve arbitrary code execution within the mutter process. This would effectively grant the attacker the ability to intercept inputs, bypass graphical sandboxing, or escalate privileges within the local user session.

## Recommendation

Prioritize the identification and patching of the GNOME mutter compositor across all Linux endpoints utilizing the GNOME desktop environment. 

- Apply the vendor-provided patch for mutter addressing CVE-2026-108094 as soon as it becomes available through the distribution's package management system.
- Implement restrictive local access controls to limit the execution of untrusted binaries or scripts that could function as malicious Wayland clients.
- Monitor local system logs for frequent crashes of the `gnome-shell` or `mutter` processes, which may indicate attempted exploitation.
