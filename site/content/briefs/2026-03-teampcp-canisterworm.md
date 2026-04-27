---
title: TeamPCP Deploys CanisterWorm on NPM After Trivy Compromise
slug: 2026-03-teampcp-canisterworm
description: TeamPCP deployed the CanisterWorm malware on the NPM package registry following a compromise of the Trivy scanning tool.
date: "2026-03-22T10:00:00Z"
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - malware
  - npm
  - canisterworm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rzqm4i/teampcp_deploys_canisterworm_on_npm_following/
  - https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise
rules:
  - title: Suspicious NPM Package Installation
    description: Detects suspicious processes related to NPM package installation, potentially indicating CanisterWorm activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Child Process of NPM
    description: Detects potentially malicious child processes spawned by NPM, indicating command execution after an exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 21, 2026, it was reported that threat actor TeamPCP successfully deployed CanisterWorm, a malicious worm, onto the NPM package registry. This followed a compromise of Trivy, a widely-used open-source vulnerability scanner. The specifics of the Trivy compromise are not detailed in this brief, but it likely involved exploiting vulnerabilities within Trivy or its infrastructure to gain unauthorized access and the ability to publish malicious packages. The scope of this incident affects…
