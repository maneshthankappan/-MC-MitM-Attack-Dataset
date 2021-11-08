

# MC-MitM Attack Signatures
This activity is a part of research work entitled "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" and describes how to identify MC-MitM attack signatures

## MC-MitM Base Variant Attack Signatures
During MC-MitM improved variant attacks, we use 11 as the rogue channel while the real channel is 1 since the real AP is operating on channel 1.
Following are the details of the dataset or network trace files
1. "Network-traffc-flow-real-channel" means the captured traffic on real channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/2799fd9a88d6).
2. "Network-traffc-flow-rogue-channel" means the captured traffic on rogue channel. This traffic flow can be [viewed online on cloudshark](https://www.cloudshark.org/captures/7efff27036ad).

### A. Filters to identify attack embark traffic flows 

#### 1. Constant Jamming Command Frame 
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1 )&& wlan.csa.channel_switch_mode

```
#### 2. Malformed Frame 
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1 )&& wlan.csa.channel_switch_mode

```
### B. Filters to identify attack headway traffic flows
#### 1. Concurrent beacons traffic flows
##### Filter for real chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==8)
```
#### 2. Concurrent probe response traffic flows
##### Filter for real chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==5)
```
##### Filter for rogue chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==5)
```

#### 3. Concurrent connection establishment(authentication) traffic flows

##### Filter for real chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==11) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 4. Concurrent connection establishment(association) traffic flows

##### Filter for real chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
##### Filter for rogue chanel
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.fc.type_subtype==1) and (wlan.addr==00:72:63:f3:0a:15)
```
#### 5. Concurrent connection establishment(EAPOL) traffic flows

##### Filter for real chanel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==1)&& (wlan.addr == 00:72:63:f3:0a:15)
```
##### Filter for rogue chanel
```
(eapol and not wlan.fc.type ==1) && (wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11)&& (wlan.addr == 00:72:63:f3:0a:15)
```
#### 6. Deauthentication/disassociation traffic flows on rogue chanel

##### Filter for deauthentication
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11 )&& (wlan.fc.type_subtype==12) and (wlan.addr == 00:72:63:f3:0a:15 or wlan.addr ==ff:ff:ff:ff:ff:ff)
```
##### Filter for disassociation
```
(wlan.bssid == 78:98:e8:50:d4:e4 ) && (wlan_radio.channel==11 )&& (wlan.fc.type_subtype==10) and (wlan.addr == 00:72:63:f3:0a:15 or wlan.addr ==ff:ff:ff:ff:ff:ff)

```

## Notes
