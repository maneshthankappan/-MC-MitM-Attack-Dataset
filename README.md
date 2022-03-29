

# MC-MitM Attack Signatures
This activity is a part of research work entitled "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" and describes how to identify MC-MitM attack signatures

## MC-MitM Base Variant Attack Signatures
During MC-MitM improved variant attacks, we use 13 as the rogue channel while the real channel is 1 since the real AP is operating on channel 1.
Following are the details of the dataset or network trace files
1. "Network-traffc-flow-real-channel" means the captured traffic on real channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" means the captured traffic on rogue channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/0487998f9748).

### A. Filters to identify stage 1 attack traffic 

#### 1. Malformed Frame 
```
(_ws.malformed) and (wlan.bssid == c0:4a:00:33:3b:62) and (wlan.fc.type_subtype ==8 or wlan.fc.type_subtype ==5)

```
### B. Filters to identify stage 2 attack traffic 
#### 1. Concurrent beacons traffic flows
##### Filter for real channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic 
##### Filter for real channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1 )&& (wlan.fc.type_subtype==5)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13 )&& (wlan.fc.type_subtype==5)
```

#### 3. Concurrent connection establishment(authentication) traffic 

##### Filter for real channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 4. Concurrent connection establishment(association) traffic 

##### Filter for real channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 5. Concurrent connection establishment(EAPOL) traffic 

##### Filter for real channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 1 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 13 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
#### 6. Concurrent data traffic 

##### Filter for real channel
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
1. "Network-traffc-flow-real-channel" means the captured traffic on real channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" means the captured traffic on rogue channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/7efff27036ad).

### A. Filters to identify stage 1 attack traffic

#### 1. Fake channel switch anouncements
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1 )&& wlan.csa.channel_switch_mode

```
### B. Filters to identify stage 2 attack traffic
#### 1. Concurrent beacons traffic flows
##### Filter for real chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
##### Filter for rogue channel
```
 (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic 
##### Filter for real channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==5)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==5)
```

#### 3. Concurrent connection establishment(authentication) traffic 

##### Filter for real channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 4. Concurrent connection establishment(association) traffic 

##### Filter for real channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 5. Concurrent connection establishment(EAPOL) traffic 
##### Filter for real channel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.addr == 00:72:63:f3:0a:15)
```
##### Filter for rogue channel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.addr == 00:72:63:f3:0a:15)
```
#### 6. Concurrent Data traffic 

##### Filter for real channel
```
(wlan.addr == c0:4a:00:33:3b:62)  and (wlan.addr == 8c:f5:a3:08:16:63)  && (wlan_radio.channel==1)&&  (wlan.fc.type_subtype==40)  
```
##### Filter for rogue channel
```
(wlan.addr == c0:4a:00:33:3b:62)  and (wlan.addr == 8c:f5:a3:08:16:63)  && (wlan_radio.channel==13)&&  (wlan.fc.type_subtype==40) 

```

## Notes
  * Attack signatures are created for educational or research purpose only. 
  * All attacks were conducted within a private network of UOC research labs.
  * Network trace does not contain any sensitive data.
  * Visit the link [How to perfrom MC-MitM Base-Variant Attacks](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Base-Variant-), which explains how we setup attack environment and recreated the attacks.
  * Visit the link [How to perfrom MC-MitM Improved-Variant Attacks](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Improved-Variant), which explains how we setup attack environment and the recreated attacks.
 
## References
  * https://github.com/vanhoefm/modwifi
  * https://github.com/lucascouto/mitm-channel-based-package
  * https://www.krackattacks.com/
  * https://www.fragattacks.com/#tools
  * https://papers.mathyvanhoef.com/acsac2014.pdf
  * https://papers.mathyvanhoef.com/ccs2018.pdf
## Ackowledgements
We thank mathy vanhoef for his support in rectifying certain issues with MC-MitM attacks. We also thank 




