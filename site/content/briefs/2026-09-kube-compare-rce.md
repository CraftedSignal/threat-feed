---
title: Arbitrary Code Execution in kube-compare via Malicious Container References
slug: 2026-09-kube-compare-rce
description: A vulnerability in kube-compare (CVE-2026-87114) allows remote code execution on the operator workstation when processing a crafted 'container://' reference path.
date: "2026-09-28T18:20:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kube_compare:kube_compare:*:*:*:*:*:*:*:*
vendors:
  - kube-compare
products:
  - kube-compare (all versions)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: When processing a 'container://' reference path, the tool incorrectly executes an untrusted container image's entrypoint instead of merely extracting data.
    confidence_band: high
cves:
  - id: CVE-2026-87114
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87114
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Inventory all workstations and build servers using kube-compare.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87114 allows remote code execution.
  mitigation_plan:
    - priority: immediate
      action: Upgrade kube-compare to the vendor-provided patch version.
      owner: IT Operations
      addresses: CVE-2026-87114
      evidence: NVD vulnerability disclosure.
---

CVE-2026-87114 is a high-severity arbitrary code execution vulnerability identified in the kube-compare utility. The flaw exists in the tool's handling of 'container://' reference paths. When the tool is instructed to process a malicious container image reference, it incorrectly triggers the execution of the image's entrypoint rather than safely extracting the required data from the stopped container. 

This behavior exposes the operator's workstation to remote code execution. Because kube-compare often interacts directly with the local Docker daemon, there is a significant risk of privilege escalation. If the Docker daemon is configured with root privileges, the malicious code executed by the container image may run with corresponding elevated system access, allowing for complete host compromise. This issue affects any environment where users leverage kube-compare to inspect untrusted or potentially compromised container images.

## Impact

The vulnerability poses a high risk of remote code execution on the workstation of any developer or administrator using the affected version of kube-compare. In environments where the Docker daemon runs with root privileges, this impact scales to full host compromise. Organizations using kube-compare for CI/CD pipelines or local development inspection workflows are at the highest risk, as they are likely to encounter untrusted container images during their build or troubleshooting processes.

## Recommendation

* Immediately update kube-compare to the latest patched version that addresses CVE-2026-87114.
* Audit CI/CD pipelines and developer workstations to identify instances where kube-compare is used to inspect container images from untrusted sources.
* Enforce the principle of least privilege by ensuring the Docker daemon is configured to run without unnecessary root privileges, limiting the potential impact of an exploited container entrypoint.
* Implement strict image provenance checks to ensure only trusted container images are processed by developer utilities.
