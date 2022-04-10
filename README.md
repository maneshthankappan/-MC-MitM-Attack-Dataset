

# MC-MitM Attack Signatures
This repository is a part of our research work entitled <p align="center">
  <img src="https://github.com/maneshthankappan/MC-MitM-Attack-Dataset/blob/main/title.png">
</p> and describes how to identify MC-MitM attack signatures in terms of specific network traffic.

## MC-MitM Base Variant Attack Signatures
During MC-MitM base variant attacks, we use 13 as the rogue channel while the legitimate channel is 1 since the AP is operating on channel 1.
Following are the details of the dataset or network trace files.
1. "Network-traffc-flow-real-channel" is the captured traffic on legitimate channel, which can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" is the captured traffic on rogue channel, which can be [viewed online on cloudshark](https://www.cloudshark.org/captures/0487998f9748).  
3. Access the above cloudshark files and apply the following filters to see respective frames.

### A. Filters to identify stage 1 attack traffic signatures
 
#### 1. Frame Inter-arrival time due to Constant Jamming 

<p align="center">
  <img src="https://github.com/maneshthankappan/MC-MitM-Attack-Dataset/blob/main/const-jam-example.png">
</p>
It is difficult to identify constant jamming behavior with above cloudshark files.Therefore, please see the yellow box in the above wireshark capture figure. Here, the arrival time between first and second beacon frame is around 82 ms, which shows that there was a constant jamming on the channel of the AP.When such jamming occurs, it drastically affect the standard deviation frame inter-arrival time. In normal conditions, the frame inter-arrival time would be 0.2 or 0.3ms if the AP transmits . If we observe this behavior for a specific time (e.g., 60 seconds),we can easily identify the frame inter-arrival time and delivery ratios to identify potential constant jamming attacks. 

#### 2. Malformed frames due to Reactive Jamming 
```
(_ws.malformed) and (wlan.bssid == c0:4a:00:33:3b:62) and (wlan.fc.type_subtype ==8 or wlan.fc.type_subtype ==5)

```
### B. Filters to identify stage 2 attack traffic 
Here, victims MAC addresses are 8c:f5:a3:08:16:63 and e4:02:9b:cd:3b:92 and APś MAC address is c0:4a:00:33:3b:62
#### 1. Concurrent beacon traffic 
##### Filter for legitimate channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic 
##### Filter for legitimate channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1 )&& (wlan.fc.type_subtype==5) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13 )&& (wlan.fc.type_subtype==5) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```

#### 3. Concurrent connection establishment(authentication) traffic 

##### Filter for legitimate channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 4. Concurrent connection establishment(association) traffic 

##### Filter for legitimate channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 5. Concurrent connection establishment(EAPOL) traffic 

##### Filter for legitimate channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 1 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 13 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
#### 6. Concurrent data traffic 

##### Filter for legitimate channel
```
(wlan.addr == c0:4a:00:33:3b:62)  and (wlan.addr == 8c:f5:a3:08:16:63)  && (wlan_radio.channel==1)&&  (wlan.fc.type_subtype==40) 
```
##### Filter for rogue channel
```
(wlan.addr == c0:4a:00:33:3b:62)  and (wlan.addr == 8c:f5:a3:08:16:63)  && (wlan_radio.channel==13)&&  (wlan.fc.type_subtype==40) 

```

## MC-MitM Improved Variant Attack Signatures
During MC-MitM improved variant attacks, we use 11 as the rogue channel while the real channel is 1 since the real AP is operating on channel 1.
Following are the details of the dataset or network trace files
1. "Network-traffc-flow-real-channel" is the captured attack traffic on legitimate channel, which can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" is the captured attack traffic on rogue channel, which can be [viewed online on cloudshark](https://www.cloudshark.org/captures/7efff27036ad).
3. Access the above cloudshark files and apply the following filters to see respective frames.

### A. Filters to identify stage 1 attack traffic signatures

#### 1. Fake channel switch announcements
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1 )&& wlan.csa.channel_switch_mode

```
### B. Filters to identify stage 2 attack traffic signatures
Here, victim MAC addresses is 00:72:63:f3:0a:15 and APś MAC address is 78:98:e8:50:d4:e4
#### 1. Concurrent beacons traffic flows
##### Filter for legitimate chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
##### Filter for rogue channel
```
 (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic 
##### Filter for legitimate channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==5)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==5)
```

#### 3. Concurrent connection establishment(authentication) traffic 

##### Filter for legitimate channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 4. Concurrent connection establishment(association) traffic 

##### Filter for legitimate channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 5. Concurrent connection establishment(EAPOL) traffic 
##### Filter for legitimate channel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.addr == 00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.addr == 00:72:63:f3:0a:15)
```
#### 6. Concurrent Data traffic 

##### Filter for legitimate channel
```
(wlan.bssid == 78:98:e8:50:d4:e4) && (wlan_radio.channel==11)&& (wlan.addr == 00:72:63:f3:0a:15) and (wlan.fc.type_subtype==32 or wlan.fc.type_subtype==40) 
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4) && (wlan_radio.channel==11)&& (wlan.addr == 00:72:63:f3:0a:15) and (wlan.fc.type_subtype==32 or wlan.fc.type_subtype==40) 

```

## Notes
  * Attack signatures are created for educational or research purpose only. 
  * All attacks were conducted within a private network of UOC research labs.
  * Network trace does not contain any sensitive data.
  * Visit the link [How to perfrom MC-MitM Base-Variant Attacks](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Base-Variant-), which explains how we setup attack environment.
  * Visit the link [How to perfrom MC-MitM Improved-Variant Attacks](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Improved-Variant), which explains how we setup attack environment.
 
## References
  * https://github.com/vanhoefm/modwifi
  * https://github.com/lucascouto/mitm-channel-based-package
  * https://www.krackattacks.com/
  * https://www.fragattacks.com/#tools
  * https://papers.mathyvanhoef.com/acsac2014.pdf
  * https://papers.mathyvanhoef.com/ccs2018.pdf





