---
brief_id: brief-2026-11-20-containerd-daemon-crash-ghsa-vwhp-8p66-mq4f
event_id: brief-2026-11-20-containerd-daemon-crash-ghsa-vwhp-8p66-mq4f
revision: 1
activity_at: "2026-11-20T02:05:43Z"
title: 'containerd: Image manifest processing denial-of-service (CVE-2026-95839)'
slug: 2026-11-containerd-daemon-crash-ghsa-vwhp-8p66-mq4f
description: A malformed digest in a child descriptor with an 'io.containerd.manifest.subject' annotation triggers an unrecovered panic in the containerd daemon, resulting in a denial-of-service.
date: "2026-11-20T02:05:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: likely
cpes:
  - cpe:2.3:a:containerd:containerd:*:*:*:*:*:*:*:*
vendors:
  - containerd
products:
  - containerd
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Pulling or importing such an image, including through a default CRI PullImage request, can trigger an unrecovered panic and crash the containerd daemon.
cves:
  - id: CVE-2026-95839
    epss: 0.00398
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-vwhp-8p66-mq4f
  - https://cveawg.mitre.org/api/cve/CVE-2026-95839
action_plan:
  hunt_leads:
    - lead: Identify repeated container daemon crash events or restarts that correlate with kubelet image pull requests, specifically looking for nodes where image pull failures occur immediately prior to daemon termination.
      technique_id: T1499
      data_needed:
        - containerd logs
        - kubelet logs
        - OS system logs (syslog/journald)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Pulling or importing such an image, including through a default CRI PullImage request, can trigger an unrecovered panic and crash the containerd daemon. In Kubernetes environments, kubelet retries failed image pulls with backoff, allowing a pod referencing an untrusted image to repeatedly crash containerd.
---

## Overview
containerd is vulnerable to a daemon-crashing denial-of-service vulnerability during image manifest processing. When the transfer service encounters a child descriptor containing the 'io.containerd.manifest.subject' annotation and a malformed digest, it triggers an unrecovered panic.

## Attack Chain
Pulling or importing an image with a malformed digest through the transfer service, including via default CRI PullImage requests, causes the containerd daemon to crash. In Kubernetes environments, kubelet retries can repeatedly trigger this crash loop, disrupting container operations on the worker node.

## Impact
Successful exploitation causes the containerd daemon to crash, disrupting container operations and availability on the affected node.

## Recommendation
This issue is fixed in containerd versions 2.2.10, 2.3.7, and 2.4.2. Users should update to these versions. As a workaround, restrict pod image references to trusted registries (for example, using a Kubernetes ValidatingAdmissionPolicy or admission webhook) and only pull or import images from trusted sources.
