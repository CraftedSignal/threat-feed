---
title: Abuse of AWS IoT Secure Tunneling Localproxy for Post-Exploitation C2
slug: 2026-09-aws-iot-tunneling-abuse
description: Adversaries are abusing the legitimate AWS IoT Secure Tunneling localproxy binary in destination mode to establish unauthorized remote access tunnels through AWS-managed infrastructure.
date: "2026-09-29T04:12:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:amazon:aws_iot_secure_tunneling:*:*:*:*:*:*:*:*
tags:
  - aws-iot
  - command-and-control
  - tunneling
  - post-exploitation
vendors:
  - Amazon
products:
  - AWS IoT Secure Tunneling
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Identifies AWS IoT Secure Tunneling localproxy started in destination mode that then resolves and connects to the Secure Tunneling data plane.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The localproxy binary creates a bidirectional relay through AWS-managed infrastructure.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: The tool facilitates protocol tunneling by relaying traffic from external sources to internal local services.
    confidence_band: high
references:
  - https://hackerhermanos.com/posts/aws-iot-secure-tunneling-red-teamer/
  - https://github.com/aws-samples/aws-iot-securetunneling-localproxy
  - https://docs.aws.amazon.com/iot/latest/developerguide/local-proxy.html
iocs:
  - type: domain
    value: '*.tunneling.iot.*.amazonaws.com'
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy EQL detection for localproxy destination mode behavior.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit EQL logic.
  enrichment_needed:
    - item: Authorized IoT asset list
      owner: IT Operations
      reason: To reduce false positives for legitimate administrative tools.
      evidence: False positive section notes use by support engineers.
  hunt_leads:
    - lead: Process executions of 'localproxy' or 'localproxy.exe' with -d or --destination-app flags.
      technique_id: T1572
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies binary as post-exploitation tool.
  mitigation_plan:
    - priority: medium
      action: Implement egress filtering on endpoints to prevent unauthorized access to tunneling data plane domains.
      owner: Network Security
      addresses: C2 activity
      evidence: Investigation guide suggests blocking *.tunneling.iot.*.amazonaws.com.
  gaps:
    - None.
---

Adversaries are leveraging the legitimate, signed AWS IoT Secure Tunneling `localproxy` binary for post-exploitation command-and-control (C2) and persistent remote access. This technique involves executing the binary on a compromised host in 'destination' mode, which instructs the proxy to establish an outbound connection to the AWS IoT Secure Tunneling data plane (`data.tunneling.iot.<region>.amazonaws.com`) via port 443. Once connected, the proxy relays traffic from the attacker's workstation to local services on the victim host, such as SSH on localhost:22. Because this tool is a documented, signed AWS component often used for legitimate device management, its execution can easily blend into authorized administrative activity. Notably, the C2 channel is established using the attacker's own AWS account credentials, leaving no `OpenTunnel` events in the victim's CloudTrail logs, making detection dependent on endpoint-level process and network behavior monitoring.

## Attack Chain

1. Attacker achieves initial access to a target host and identifies it as a candidate for persistent remote access.
2. Attacker drops the legitimate `localproxy` binary onto the target filesystem or uses an existing copy if available.
3. Attacker executes `localproxy` with destination-mode flags (e.g., `-d`, `--destination-app`, or `-m dst`) to prepare the host to receive tunnel traffic.
4. The `localproxy` process initiates a DNS lookup for the AWS Secure Tunneling data plane endpoint (`data.tunneling.iot.<region>.amazonaws.com`).
5. The process establishes an outbound TCP/443 connection to the resolved AWS endpoint to register the destination.
6. Attacker initiates a connection from their own infrastructure through the Secure Tunneling service.
7. `localproxy` receives the traffic from the tunnel and forwards it to the specified local service (e.g., TCP 127.0.0.1:22).
8. Attacker gains interactive access to the victim host through the established relay.

## Impact

Successful abuse of this technique provides adversaries with a stealthy, persistent, and authorized-looking C2 channel that bypasses many traditional perimeter defenses. It enables unauthorized remote access to internal services, potential data exfiltration, and lateral movement from the compromised host, all while utilizing AWS-managed infrastructure that is often implicitly trusted by corporate security policies.

## Recommendation

Prioritize the implementation of process and network correlation rules to detect unauthorized execution of the `localproxy` binary.
- Deploy the provided EQL detection rule to your SIEM and tune against known-legitimate administrative device-management activity.
- Monitor for and alert on DNS queries to `*.tunneling.iot.*.amazonaws.com` originating from endpoints not explicitly authorized for AWS IoT device management.
- Isolate hosts where `localproxy` is identified without a corresponding business justification and block the C2 domain at the DNS or egress firewall level.
- Investigate any local connections from the `localproxy` process to sensitive local services like SSH (22) or RDP (3389) during the process execution window.
