

# MC-MitM Attack Signatures
This activity is a part of research work entitled "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" and describes how to identify MC-MitM attack signatures

## MC-MitM Base Variant Attack Signatures
During MC-MitM improved variant attacks, we use 11 as the rogue channel while the real channel is 1 since the real AP is operating on channel 1.
Following are the details of the dataset or network trace files
1. "Network-traffc-flow-real-channel" means the captured traffic on real channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" means the captured traffic on rogue channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/0487998f9748).

### A. Filters to identify attack embark traffic flows 
Note: Filter on real channel
#### 1. Constant Jamming Command Frame 
```
wlan.da== 88:88:88:88:88:88 or wlan.addr== 88:88:88:88:88:88

```
#### 2. Malformed Frame 
```
(_ws.malformed) and (wlan.bssid == c0:4a:00:33:3b:62) and (wlan.fc.type_subtype ==8 or wlan.fc.type_subtype ==5)

```
### B. Filters to identify attack headway traffic flows
#### 1. Concurrent beacons traffic flows
##### Filter for real channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic flows
##### Filter for real channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1 )&& (wlan.fc.type_subtype==5)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13 )&& (wlan.fc.type_subtype==5)
```

#### 3. Concurrent connection establishment(authentication) traffic flows

##### Filter for real channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
 (wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==11) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 4. Concurrent connection establishment(association) traffic flows

##### Filter for real channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(wlan.bssid == c0:4a:00:33:3b:62 ) and  (wlan_radio.channel==13)&& (wlan.fc.type_subtype==1) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr == e4:02:9b:cd:3b:92)
```
#### 5. Concurrent connection establishment(EAPOL) traffic flows

##### Filter for real channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 1 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
##### Filter for rogue channel
```
(eapol and not wlan.fc.type ==1) && wlan_radio.channel == 13 &&  (wlan.bssid == c0:4a:00:33:3b:62 ) && (wlan.addr== 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92)
```
#### 6. Deauthentication/disassociation traffic flows on rogue channel

##### Filter for deauthentication
```
(wlan.bssid == c0:4a:00:33:3b:62 )  and wlan_radio.channel == 13&& (wlan.fc.type_subtype==12) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92 or wlan.addr ==ff:ff:ff:ff:ff:ff)
```
##### Filter for disassociation
```
(wlan.bssid == c0:4a:00:33:3b:62 )  and wlan_radio.channel == 13&& (wlan.fc.type_subtype==10) and (wlan.addr == 8c:f5:a3:08:16:63 or wlan.addr== e4:02:9b:cd:3b:92 or wlan.addr ==ff:ff:ff:ff:ff:ff)

```

## Notes
