---
brief_id: brief-2026-11-01-beta9-worker-breakout
event_id: brief-2026-11-01-beta9-worker-breakout
revision: 1
activity_at: "2026-11-01T14:53:46Z"
title: 'Beta9: Build worker isolation deficiency (CVE-2026-120306)'
slug: 2026-11-beta9-worker-breakout
description: Beta9 worker pods execute tenant image definition shell commands with inadequate isolation, allowing access to the worker's filesystem and privileged resources.
date: "2026-11-01T14:53:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - container-security
  - privilege-escalation
  - vulnerability
products:
  - Beta9 worker (prior to 0.1.756)
cves:
  - id: CVE-2026-120306
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120306
---

Beta9 worker pods perform image builds using Buildah with insufficient isolation. Tenant-provided shell commands are executed as RUN instructions within the worker, which shares PID, network, IPC, and user namespaces with the build worker container. The worker runs as UID 0 with CAP_DAC_OVERRIDE. Access to /proc/1/root allows the build process to interact with the worker's filesystem, which contains runc, buildah, and runsc binaries, Kubernetes service account tokens, and mounted host directories.
