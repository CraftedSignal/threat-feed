---
title: 'BTMOB Android RAT: MaaS Platform Targeting Android Devices'
slug: 2026-05-btmob-android-rat
description: BTMOB is a Malware-as-a-Service (MaaS) Android RAT, first observed in February 2025, that uses phishing lures and the abuse of Android Accessibility Services to gain control of devices for data exfiltration, screen capture, and remote access.
date: "2026-05-27T06:58:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - android
  - rat
  - malware
  - maas
  - btmob
  - trojan
vendors:
  - Google
products:
  - Google Play
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/
iocs:
  - type: ip
    value: 74.125.202.103
  - type: ip
    value: 142.251.183.138
  - type: ip
    value: 173.194.193.138
  - type: ip
    value: 173.194.206.106
  - type: ip
    value: 178.156.177.192
  - type: ip
    value: 191.101.131.250
  - type: ip
    value: 195.160.221.203
  - type: ip
    value: 104.21.64.137
  - type: ip
    value: 173.194.194.94
  - type: ip
    value: 191.96.224.87
  - type: ip
    value: 191.96.225.241
  - type: ip
    value: 191.96.78.172
  - type: ip
    value: 191.96.78.28
  - type: ip
    value: 191.96.79.133
  - type: ip
    value: 191.96.79.179
  - type: ip
    value: 191.96.79.41
  - type: ip
    value: 192.178.209.95
  - type: ip
    value: 200.9.155.153
  - type: ip
    value: 74.125.132.95
  - type: ip
    value: 78.135.93.123
  - type: ip
    value: 79.133.57.141
  - type: domain
    value: arbsniper.com
  - type: hash_sha256
    value: 58AC130A8EBB09E37592AC69841483EDC5695D1545B1F04F23D5B760AC17CD94
  - type: hash_sha256
    value: 0A542751724A432A8448324613E0CE10393E41739A1800CBB7D5A2C648FCDC35
  - type: hash_sha256
    value: A764D73795ABE47AE640BA09999A18C47B5340E5ECC7B897AFEBF34F3F37638F
  - type: hash_sha256
    value: 26A2268281E8043125EF72B92F8980B42912048753D56894BC378FB54C7C188A
  - type: hash_sha256
    value: 6AE94CE710016D86ED7457236DEEF2C4C51478587F3609B6E827A348828B3931
  - type: hash_sha256
    value: E5A9FDFF900DD502E8F3DCE52D2D1B69AA9AFAFB5094A28F9037E8770DB0E63B
  - type: hash_sha256
    value: C6199E175FB988CBBEACDF0F5ACDF9ED83F5BDAAE5C95B7A6C27EE72CD11B0B1
  - type: hash_sha256
    value: 6BBA64FA9E8A7B11CB2476CD071DE08986DB44B0783EFF211C68FA5594EF8143
  - type: hash_sha256
    value: 5AAAF972C8BF39A98F2748E526DE3CC0370BA831997D7D9765CDABA599645C0D
  - type: hash_sha256
    value: DDCE0219923D152B8FACD303F058A6286CF1F6924992B9FB9F5BF4D96436CC39
  - type: hash_sha256
    value: D55057CD9110D12A192281356F06B94F342B9FEBB305CF0A5898A7E6AF40758F
  - type: hash_sha256
    value: 676CB2D0A60403AFC06CEA1B572CB7261F706365FAC65621B5A4907893E7AC0D
  - type: hash_sha256
    value: 75DD4FB011ED598374A46FC0D9C0D1D64A298341C34AFC83A56A6983CFD27764
  - type: hash_sha256
    value: 702261BA38B57ECC3A5407FED28B2F0611A74C2EC0C116AEA4F9E6DEF0899AED
  - type: hash_sha256
    value: 998A7ED1572AD9DC11375BC25294E1954E606B7CFF9FABC5C120713E597CD274
  - type: hash_sha256
    value: 244D81FD9908CD17815501D4EDADEB1BAF1C421AA25D8BD61C7CB481C939540E
  - type: hash_sha256
    value: 512EDE9F2FA794907999F3C26165557FDFD383B7AAD71BA022CE2C8BA6C0019D
  - type: hash_sha256
    value: 7AC974899E8E05AAACD417577C97E382D5E8C5F7F4A85632CFFB47EC2F6AE4E0
  - type: hash_sha256
    value: 168F50BF9A87099094EF410E3AC33E676A6A8740A5437CD09E7B63D73DF8431A
  - type: hash_sha256
    value: 2525D1E427A9983B0B4CA0906A4B44FFB9814B23D53FD8A2E3AB6512B027C733
  - type: hash_sha256
    value: 6101D1E1811DB052F869F7EB3402DAD28DA7E92103D4A44EE43F95846A075012
  - type: hash_sha256
    value: 1A60CB5F7E2FB7C09FC3DC8459108B26AC98EE73131F37A28CFDAD5FC75B7A7D
  - type: hash_sha256
    value: 97A0497DE585D3BE6EC75064AB3BD0979CD85561193C1F0669CCF4DB31330687
  - type: hash_sha256
    value: 02A52C4CC11748D44C9B49D508EE4E46425661981FA1406F30EC0830CB69DDC5
  - type: hash_sha256
    value: 6F9832EBB4C3054BEE4A6CE5CCB69C00E2020053E1308353343097E6A4041109
  - type: hash_sha256
    value: F76B13040C634F82A8332FF9443D84C89A5BCED51AE9ADAD7FD15C05FADB4324
  - type: hash_sha256
    value: C99139B0053C4C698EA0246D26D747F2A984C7ABA4613DA818ECD9F97899EF3A
  - type: hash_sha256
    value: 8F09274E808E0063D51F34CAC82A5770B3DF30C792E426DA2F6A80657F27AFFC
  - type: hash_sha256
    value: 140A7F995B0336942691A2E93E2017FD575267C017C7D0728D69169306F91963
  - type: hash_sha256
    value: A1E457C52EAB430C20D48F2AC476E080386313F16EFB135A0471902CF68CE475
  - type: hash_sha256
    value: 5A4E86BBCF0EBC455D2995DB225D9AD682E9B37B6BAD472A604A462099D988BD
  - type: hash_sha256
    value: A892F1EF2E530D67BF948A48C734DA3F27718EB8B883CA0B686DDB0A81071731
  - type: hash_sha256
    value: AA56F350882CE63429C6626567487B041F06168BB60F4FC371A262EABADFA660
  - type: hash_sha256
    value: 752C1CFE783ED343E470AB95A4843A23872CDC98B7D3ED5633DD6C881C071A14
  - type: hash_sha256
    value: 0628AD6D1FD836B13B22E75FA169502D8CE78B7AD20F0261EB5151DA98437BCA
  - type: hash_sha256
    value: 6844CE1539014571360495C6FB50965E813C2721663BDD40D577D9E5163773C6
ioc_counts:
  domain: 1
  hash_sha256: 36
  ip: 21
rules:
  - title: Detect BTMOB Installation via PackageInstaller
    description: Detects potential BTMOB RAT installation attempts by monitoring for package installations initiated by PackageInstaller with specific package names.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - android
  - title: Detect Network Connection to BTMOB Infrastructure
    description: Detects network connections to known BTMOB command and control infrastructure.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - android
rules_count: 2
---

BTMOB is an Android Remote Access Trojan (RAT) that has evolved from the SpySolr malware, first described in February 2025. Unlike banking trojans, BTMOB offers adversaries a broader range of options, including exfiltration of sensitive data, screen capture, activity recording, and remote device control. The RAT is sold with an APK builder interface, enabling anyone to generate new payloads and tailor phishing lures for specific regions without requiring coding skills. BTMOB is marketed as a software product via promotional pages and social media platforms, with license fees reported around $5,000 plus monthly support, lowering the barrier for less sophisticated adversaries. In January 2026, claims surfaced of BTMOB-related files being offered for free on a dark web forum, indicating a risk of wider availability. ESET products detect the primary tool as MSIL/BtmobRat, while related Android variants trigger detections such as Android/Spy.Agent.EED, Android/Spy.Agent.EIJ and Android/Spy.Agent.EIK.

## Attack Chain

1.  The attacker designs a phishing website impersonating a streaming service or cryptocurrency mining platform.
2.  The victim receives a link to the phishing website via email, messaging app, or social media.
3.  The victim is redirected to a fake app store mimicking legitimate repositories like Google Play.
4.  The victim is prompted to download and install a malicious APK file containing the BTMOB RAT.
5.  Upon installation, BTMOB requests extensive permissions, abusing Android Accessibility Services to gain elevated access without further user interaction.
6.  BTMOB gains control of the device, enabling data exfiltration, screen capture, and activity recording.
7.  The attacker can remotely control the device to perform unauthorized actions or access sensitive information.
8.  The attacker exfiltrates data from the compromised device.

## Impact

Compromised Android devices can lead to significant data breaches, financial loss, and privacy violations. BTMOB allows attackers to steal credentials, intercept communications, capture sensitive information displayed on the screen, and remotely control the device. The malware's ability to adapt phishing lures quickly and its availability as a MaaS platform expands its reach and impact, affecting users who are lured into installing the application under false pretenses. Successful attacks could expose sensitive corporate data if employees use their devices for work purposes.

## Recommendation

*   Block the listed IP addresses and domain at network perimeters based on the IOC table to prevent communication with known BTMOB infrastructure.
*   Deploy the Sigma rule "Detect BTMOB Installation via PackageInstaller" to detect BTMOB RAT installation attempts based on package names.
*   Implement policies mandating that users download software exclusively from official repositories like Google Play to prevent installations from fake app stores.
*   Educate users to treat unsolicited links delivered via email, messaging apps, social media, and targeted advertisements with suspicion.
