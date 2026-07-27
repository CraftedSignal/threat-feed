---
title: Network Communication With Crypto Mining Pools
slug: 2026-07-crypto-mining-pool-comm
description: Crypto mining malware, often deployed by various threat actors, connects to designated mining pools to perform unauthorized cryptocurrency mining, leading to significant system performance degradation and illicit resource consumption.
date: "2026-07-27T16:39:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cryptojacking
  - resource-hijacking
  - malware
  - network-connection
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: Detects initiated network connections to crypto mining pools. It indicates that the system is likely infected with a crypto miner malware or is being used for crypto mining.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_crypto_mining_pools.yml
  - https://www.poolwatch.io/coin/monero
  - https://github.com/stamparm/maltrail/blob/da082537e0f37b9dece3a6998583e43bb5709c4e/trails/static/suspicious/crypto_mining.txt
  - https://www.virustotal.com/gui/search/behaviour_network%253A*.miningocean.org/files
iocs:
  - type: domain
    value: aeon-pool.com
  - type: domain
    value: alimabi.cn
  - type: domain
    value: ap.luckpool.net
  - type: domain
    value: api.fastpool.xyz
  - type: domain
    value: auto.c3pool.org
  - type: domain
    value: awgoaigartnj-xmr.com
  - type: domain
    value: backup.fastpool.xyz
  - type: domain
    value: bcn.pool.minergate.com
  - type: domain
    value: bcn.vip.pool.minergate.com
  - type: domain
    value: bizxmr.cc
  - type: domain
    value: bmpool.org
  - type: domain
    value: bohemianpool.com
  - type: domain
    value: byw.dscloud.me
  - type: domain
    value: c3.wptask.cyou
  - type: domain
    value: c3pool.org
  - type: domain
    value: ca-aipg.miningocean.org
  - type: domain
    value: ca-dynex.miningocean.org
  - type: domain
    value: ca-neurai.miningocean.org
  - type: domain
    value: ca-qrl.miningocean.org
  - type: domain
    value: ca-upx.miningocean.org
  - type: domain
    value: ca-zephyr.miningocean.org
  - type: domain
    value: ca.minexmr.com
  - type: domain
    value: ca.monero.herominers.com
  - type: domain
    value: cbd.monerpool.org
  - type: domain
    value: cbdv2.monerpool.org
  - type: domain
    value: community-pools.mysrv.cloud
  - type: domain
    value: covid19crypto.com
  - type: domain
    value: cryptmonero.com
  - type: domain
    value: crypto-pool.fr
  - type: domain
    value: crypto-pool.info
  - type: domain
    value: cryptominded.com
  - type: domain
    value: cryptonight-hub.miningpoolhub.com
  - type: domain
    value: d1pool.ddns.net
  - type: domain
    value: d5pool.us
  - type: domain
    value: daili01.monerpool.org
  - type: domain
    value: de-aipg.miningocean.org
  - type: domain
    value: de-dynex.miningocean.org
  - type: domain
    value: de-zephyr.miningocean.org
  - type: domain
    value: de.minexmr.com
  - type: domain
    value: de.moneroocean.stream
  - type: domain
    value: de.salvium.herominers.com
  - type: domain
    value: de.zephyr.herominers.com
  - type: domain
    value: dl.nbminer.com
  - type: domain
    value: donate.graef.in
  - type: domain
    value: donate.ssl.xmrig.com
  - type: domain
    value: donate.v2.xmrig.com
  - type: domain
    value: donate.xmrig.com
  - type: domain
    value: donate2.graef.in
  - type: domain
    value: drill.moneroworld.com
  - type: domain
    value: dwarfpool.com
  - type: domain
    value: emercoin.com
  - type: domain
    value: emercoin.net
  - type: domain
    value: emergate.net
  - type: domain
    value: ethereumpool.co
  - type: domain
    value: eu.luckpool.net
  - type: domain
    value: eu.minerpool.pw
  - type: domain
    value: f2pool.com
  - type: domain
    value: fastpool.xyz
  - type: domain
    value: fcn-xmr.pool.minergate.com
  - type: domain
    value: fee.xmrig.com
  - type: domain
    value: fi.moneroocean.stream
  - type: domain
    value: fr-aipg.miningocean.org
  - type: domain
    value: fr-dynex.miningocean.org
  - type: domain
    value: fr-neurai.miningocean.org
  - type: domain
    value: fr-qrl.miningocean.org
  - type: domain
    value: fr-tarirx.luckypool.io
  - type: domain
    value: fr-upx.miningocean.org
  - type: domain
    value: fr-zephyr.miningocean.org
  - type: domain
    value: fr.minexmr.com
  - type: domain
    value: fr.moneroocean.stream
  - type: domain
    value: friendspool.club
  - type: domain
    value: ftp.fastpool.xyz
  - type: domain
    value: gandalph3000.com
  - type: domain
    value: googleminer.com
  - type: domain
    value: grin.2miners.com
  - type: domain
    value: gulf.moneroocean.stream
  - type: domain
    value: hellominer.com
  - type: domain
    value: herominers.com
  - type: domain
    value: hk-aipg.miningocean.org
  - type: domain
    value: hk-dynex.miningocean.org
  - type: domain
    value: hk-neurai.miningocean.org
  - type: domain
    value: hk-qrl.miningocean.org
  - type: domain
    value: hk-upx.miningocean.org
  - type: domain
    value: hk-zephyr.miningocean.org
  - type: domain
    value: hns.f2pool.com
  - type: domain
    value: huadong1-aeon.ppxxmr.com
  - type: domain
    value: imap.fastpool.xyz
  - type: domain
    value: iwanttoearn.money
  - type: domain
    value: joulecoin.org
  - type: domain
    value: jp.moneroocean.stream
  - type: domain
    value: jw-js1.ppxxmr.com
  - type: domain
    value: koto-pool.work
  - type: domain
    value: kronecoin.org
  - type: domain
    value: kryptex.network
  - type: domain
    value: kubo.ultra-pool.com
  - type: domain
    value: lhr.nbminer.com
  - type: domain
    value: lhr3.nbminer.com
  - type: domain
    value: linux.monerpool.org
  - type: domain
    value: litecoinpool.org
  - type: domain
    value: lokiturtle.herominers.com
  - type: domain
    value: luckpool.net
  - type: domain
    value: luckypool.io
  - type: domain
    value: mail.fastpool.xyz
  - type: domain
    value: masari.miner.rocks
  - type: domain
    value: mine.aeon-pool.com
  - type: domain
    value: mine.bmpool.org
  - type: domain
    value: mine.c3pool.com
  - type: domain
    value: mine.fastpool.xyz
  - type: domain
    value: mine.lesliejust.is
  - type: domain
    value: mine.moneropool.com
  - type: domain
    value: mine.ppxxmr.com
  - type: domain
    value: mine.zpool.ca
  - type: domain
    value: mine1.ppxxmr.com
  - type: domain
    value: minemonero.gq
  - type: domain
    value: miner.ppxxmr.com
  - type: domain
    value: miner.rocks
  - type: domain
    value: minercircle.com
  - type: domain
    value: minergate.com
  - type: domain
    value: minerpool.pw
  - type: domain
    value: minerrocks.com
  - type: domain
    value: miners.pro
  - type: domain
    value: minerxmr.ru
  - type: domain
    value: minexmr.cn
  - type: domain
    value: minexmr.com
  - type: domain
    value: mining-help.ru
  - type: domain
    value: mining.bittubeapp.com
  - type: domain
    value: miningocean.org
  - type: domain
    value: miningpoolhub.com
  - type: domain
    value: miningrigrentals.com
  - type: domain
    value: mixpools.org
  - type: domain
    value: moner.monerpool.org
  - type: domain
    value: moner1min.monerpool.org
  - type: domain
    value: monero-master.crypto-pool.fr
  - type: domain
    value: monero.crypto-pool.fr
  - type: domain
    value: monero.hashvault.pro
  - type: domain
    value: monero.herominers.com
  - type: domain
    value: monero.lindon-pool.win
  - type: domain
    value: monero.miners.pro
  - type: domain
    value: monero.riefly.id
  - type: domain
    value: monero.us.to
  - type: domain
    value: monerocean.stream
  - type: domain
    value: monerogb.com
  - type: domain
    value: monerohash.com
  - type: domain
    value: moneroocean.stream
  - type: domain
    value: monerooceans.stream
  - type: domain
    value: moneropool.com
  - type: domain
    value: moneropool.nl
  - type: domain
    value: monerorx.com
  - type: domain
    value: monerpool.org
  - type: domain
    value: moriaxmr.com
  - type: domain
    value: mro.pool.minergate.com
  - type: domain
    value: multipool.us
  - type: domain
    value: myxmr.pw
  - type: domain
    value: na.luckpool.net
  - type: domain
    value: nanopool.org
  - type: domain
    value: nbminer.com
  - type: domain
    value: node.btx.tools
  - type: domain
    value: node3.luckpool.net
  - type: domain
    value: noobxmr.com
  - type: domain
    value: p06.2miners.com
  - type: domain
    value: pangolinminer.com
  - type: domain
    value: pool-de.supportxmr.com
  - type: domain
    value: pool-fr.supportxmr.com
  - type: domain
    value: pool-nyc.supportxmr.com
  - type: domain
    value: pool-phx.supportxmr.com
  - type: domain
    value: pool.4i7i.com
  - type: domain
    value: pool.armornetwork.org
  - type: domain
    value: pool.awgoaigartnj-xmr.com
  - type: domain
    value: pool.cortins.tk
  - type: domain
    value: pool.gntl.co.uk
  - type: domain
    value: pool.hashvault.pro
  - type: domain
    value: pool.minergate.com
  - type: domain
    value: pool.minexmr.com
  - type: domain
    value: pool.minexmr.uk
  - type: domain
    value: pool.monero.hashvault.pro
  - type: domain
    value: pool.ppxxmr.com
  - type: domain
    value: pool.somec.cc
  - type: domain
    value: pool.support
  - type: domain
    value: pool.supportxmr.com
  - type: domain
    value: pool.usa-138.com
  - type: domain
    value: pool.xmr.pt
  - type: domain
    value: pool.xmrfast.com
  - type: domain
    value: pool2.armornetwork.org
  - type: domain
    value: poolchange.ppxxmr.com
  - type: domain
    value: pooldd.com
  - type: domain
    value: poolmining.org
  - type: domain
    value: poolto.be
  - type: domain
    value: pop.fastpool.xyz
  - type: domain
    value: ppxvip1.ppxxmr.com
  - type: domain
    value: ppxxmr.com
  - type: domain
    value: prohash.net
  - type: domain
    value: r.twotouchauthentication.online
  - type: domain
    value: randomx.xmrig.com
  - type: domain
    value: ratchetmining.com
  - type: domain
    value: rx.unmineable.com
  - type: domain
    value: salvium.herominers.com
  - type: domain
    value: seed.emercoin.com
  - type: domain
    value: seed.emercoin.net
  - type: domain
    value: seed.emergate.net
  - type: domain
    value: seed.kronecoin.org
  - type: domain
    value: seed.titcoinpool.com
  - type: domain
    value: seed.titcoins.info
  - type: domain
    value: seed1.joulecoin.org
  - type: domain
    value: seed2.joulecoin.org
  - type: domain
    value: seed3.joulecoin.org
  - type: domain
    value: seed4.joulecoin.org
  - type: domain
    value: seed5.joulecoin.org
  - type: domain
    value: seed6.joulecoin.org
  - type: domain
    value: seed7.joulecoin.org
  - type: domain
    value: seed8.joulecoin.org
  - type: domain
    value: sg-aipg.miningocean.org
  - type: domain
    value: sg-dynex.miningocean.org
  - type: domain
    value: sg-neurai.miningocean.org
  - type: domain
    value: sg-qrl.miningocean.org
  - type: domain
    value: sg-upx.miningocean.org
  - type: domain
    value: sg-zephyr.miningocean.org
  - type: domain
    value: sg.minexmr.com
  - type: domain
    value: sheepman.mine.bz
  - type: domain
    value: siamining.com
  - type: domain
    value: smtp.fastpool.xyz
  - type: domain
    value: solarray.club
  - type: domain
    value: solo-grin.2miners.com
  - type: domain
    value: solo-grin.2miners.ru
  - type: domain
    value: solo-xmr.2miners.com
  - type: domain
    value: solo-xmr.2miners.ru
  - type: domain
    value: soloxmr2min.dyndns.org
  - type: domain
    value: sparechange.io
  - type: domain
    value: ssl.fastpool.xyz
  - type: domain
    value: sumokoin.minerrocks.com
  - type: domain
    value: supportxmr.com
  - type: domain
    value: suprnova.cc
  - type: domain
    value: system-check.services
  - type: domain
    value: system-update.info
  - type: domain
    value: teracycle.net
  - type: domain
    value: titcoinpool.com
  - type: domain
    value: titcoins.info
  - type: domain
    value: tpool.yiluzhuanqian.com
  - type: domain
    value: trtl.cnpool.cc
  - type: domain
    value: trtl.pool.mine2gether.com
  - type: domain
    value: turtle.miner.rocks
  - type: domain
    value: ultra-pool.com
  - type: domain
    value: unmineable.com
  - type: domain
    value: us-aipg.miningocean.org
  - type: domain
    value: us-dynex.miningocean.org
  - type: domain
    value: us-grin.2miners.com
  - type: domain
    value: us-neurai.miningocean.org
  - type: domain
    value: us-west.minexmr.com
  - type: domain
    value: us-zephyr.miningocean.org
  - type: domain
    value: usxmrpool.com
  - type: domain
    value: viaxmr.com
  - type: domain
    value: web.xmrpool.eu
  - type: domain
    value: webservicepag.webhop.net
  - type: domain
    value: winxmr.club
  - type: domain
    value: x109.node.btx.tools
  - type: domain
    value: xcn1.yiluzhuanqian.com
  - type: domain
    value: xiazai.monerpool.org
  - type: domain
    value: xiazai1.monerpool.org
  - type: domain
    value: xmc.pool.minergate.com
  - type: domain
    value: xmo.pool.minergate.com
  - type: domain
    value: xmr-asia1.nanopool.org
  - type: domain
    value: xmr-au1.nanopool.org
  - type: domain
    value: xmr-eu1.nanopool.org
  - type: domain
    value: xmr-eu2.nanopool.org
  - type: domain
    value: xmr-jp1.nanopool.org
  - type: domain
    value: xmr-us-east1.nanopool.org
  - type: domain
    value: xmr-us-west1.nanopool.org
  - type: domain
    value: xmr-us.suprnova.cc
  - type: domain
    value: xmr-usa.dwarfpool.com
  - type: domain
    value: xmr.2miners.com
  - type: domain
    value: xmr.5b6b7b.ru
  - type: domain
    value: xmr.748pz.net
  - type: domain
    value: xmr.alimabi.cn
  - type: domain
    value: xmr.bepooh.com
  - type: domain
    value: xmr.bohemianpool.com
  - type: domain
    value: xmr.crypto-pool.fr
  - type: domain
    value: xmr.crypto-pool.info
  - type: domain
    value: xmr.f2pool.com
  - type: domain
    value: xmr.hashcity.org
  - type: domain
    value: xmr.hex7e4.ru
  - type: domain
    value: xmr.ip28.net
  - type: domain
    value: xmr.kryptex.network
  - type: domain
    value: xmr.monerpool.org
  - type: domain
    value: xmr.mypool.online
  - type: domain
    value: xmr.nanopool.org
  - type: domain
    value: xmr.pool.gntl.co.uk
  - type: domain
    value: xmr.pool.minergate.com
  - type: domain
    value: xmr.poolto.be
  - type: domain
    value: xmr.ppxxmr.com
  - type: domain
    value: xmr.prohash.net
  - type: domain
    value: xmr.simka.pw
  - type: domain
    value: xmr.somec.cc
  - type: domain
    value: xmr.suprnova.cc
  - type: domain
    value: xmr.usa-138.com
  - type: domain
    value: xmr.vip.pool.minergate.com
  - type: domain
    value: xmr.yiluzhuanqian.com
  - type: domain
    value: xmr1min.monerpool.org
  - type: domain
    value: xmrf.520fjh.org
  - type: domain
    value: xmrf.fjhan.club
  - type: domain
    value: xmrfast.com
  - type: domain
    value: xmrigcc.graef.in
  - type: domain
    value: xmrminer.cc
  - type: domain
    value: xmrpool.de
  - type: domain
    value: xmrpool.eu
  - type: domain
    value: xmrpool.me
  - type: domain
    value: xmrpool.net
  - type: domain
    value: xmrpool.xyz
  - type: domain
    value: xx11m.monerpool.org
  - type: domain
    value: xx11mv2.monerpool.org
  - type: domain
    value: xxx.hex7e4.ru
  - type: domain
    value: yes.fastpool.xyz
  - type: domain
    value: zarabotaibitok.ru
  - type: domain
    value: zeph-eu2.nanopool.org
  - type: domain
    value: zeph.2miners.com
  - type: domain
    value: zephyr.herominers.com
  - type: domain
    value: zer0day.ru
ioc_counts:
  domain: 315
rules:
  - title: Network Communication With Crypto Mining Pool
    description: Detects initiated network connections from Windows systems to known cryptocurrency mining pools, indicating potential cryptojacking or malware infection.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1496
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

This threat involves the unauthorized use of compromised systems for cryptocurrency mining, a practice known as cryptojacking. Unspecified threat actors deploy specialized malware that hijacks a victim's computing resources (CPU, GPU) to mine cryptocurrencies such as Monero. The malware then communicates with public or private mining pools to contribute its processing power and receive payouts, often anonymously. This activity significantly degrades system performance, increases power consumption, and can lead to hardware wear, resulting in operational disruption and financial costs for the victim organization. The detection focuses on identifying the characteristic network connections to known crypto mining pool domains, indicating an active infection.

## Attack Chain

1. **Initial Access**: Threat actors gain unauthorized access to a victim's system or network through various means, such as exploiting vulnerabilities, delivering malicious payloads via phishing campaigns, or bundling malware with legitimate software.
2. **Malware Delivery and Installation**: The crypto mining malware is delivered to the compromised system and installed, often masquerading as a benign application or service to avoid detection.
3. **Persistence Establishment**: The malware establishes persistence mechanisms, such as modifying registry run keys, creating scheduled tasks, or adding itself to startup folders, to ensure continuous operation across system reboots.
4. **Resource Assessment**: Upon execution, the mining software often performs an initial assessment of the system's available computing resources (CPU, GPU, memory) to optimize its mining operations and avoid immediate detection by overwhelming the system.
5. **Mining Process Initiation**: The crypto miner process starts, allocating a significant portion of the system's CPU and/or GPU cycles to perform cryptographic computations required for mining.
6. **Network Communication to Pool**: The miner establishes an outbound network connection to a pre-configured or hardcoded cryptocurrency mining pool domain to receive mining tasks and submit completed work.
7. **Data Exchange and Payout**: The miner continuously exchanges data with the mining pool, submitting cryptographic proof-of-work and receiving new blocks or tasks, with the objective of receiving cryptocurrency rewards for the attacker.
8. **Resource Hijacking Impact**: Prolonged and unauthorized mining operations lead to severe system performance degradation, increased electricity bills, and potential hardware overheating or damage, disrupting normal business operations.

## Impact

Successful cryptojacking attacks result in substantial resource consumption on compromised systems, leading to noticeable performance degradation, increased electricity usage, and accelerated wear and tear on hardware components. While the primary financial gain is for the attacker, organizations bear the cost of increased operational expenses and potential system downtime. The broad targeting nature of this threat means any organization with vulnerable internet-facing assets or endpoints susceptible to malware delivery could be affected, leading to widespread impact on productivity and infrastructure stability across various sectors.

## Recommendation

* Deploy the provided Sigma rule "Network Communication With Crypto Mining Pool" to your SIEM or EDR solution to detect outbound connections to known mining pools.
* Block all domains listed in the IOC table at your network perimeter firewall or DNS resolver to prevent miner communication.
* Monitor network connection logs from Windows endpoints for unusual outbound connections, specifically targeting the `DestinationHostname` field.
* Regularly patch and update all operating systems and software to prevent initial access via known vulnerabilities.
