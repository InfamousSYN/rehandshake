# rehandshake
a tool for automatically repairing of partially captured 4-way handshakes to yield a PCAP which can be used by `hcxpcapngtool` to produce hash outputs to be subsequentially pushed through `hashcat` to uncover the Pre-Shared Key (PSK).
1. **Repair Technique 1:** Checks EAPOL Message 1 frame for a PMKID value, if the frame contains the required fields, and then checks if a Beacon frame for associated WLAN exists. If the target Beacon frame doesn't exist, a frame is crafted based on the provided `--ssid` argument value (it is assumed the user knows the desired SSID). The resulting 2 frame pair is written to a PCAP file.
2. **Repair Technique 2:** Checks for a EAPOL Message 1 and Message 2 frame pair (`EAPOL M12E2 (challenge)`)for an associated WLAN, and then checks if a Beacon frame for associated WLAN exists. If the target Beacon frame doesn't exist, a frame is crafted based on the provided `--ssid` argument value (it is assumed the user knows the desired SSID). The resulting 3 frame sequence is written to a PCAP file. 
3. **Repair Technique 3:** Checks for a EAPOL Message 2 and Message 3 frame pair (`EAPOL M32E2 (authorized)`)for an associated WLAN, and then checks if a Beacon frame for associated WLAN exists. If the target Beacon frame doesn't exist, a frame is crafted based on the provided `--ssid` argument value (it is assumed the user knows the desired SSID). An EAPOL Message 1 frame is automatically crafted to match the  The resulting 4 frame sequence is written to a PCAP file.

# Install
1. scapy

```python
python3 -m pip install scapy
```

# Usage
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ python3 rehandshake.py -h
usage: rehandshake.py [-h] [--version] [--verbose] [--file IN_FILE] [--output-file OUT_FILE] [--SSID SSID] [--all] [-1] [-2] [-3]

Automated tool for repairing broken 4-way handshakes

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --verbose, -v
  --file IN_FILE, -f IN_FILE
                        specify pcap file containing the handshake
  --output-file OUT_FILE, -o OUT_FILE
                        specify name for repaired pcap file

  Controls for specifying target SSID

  --SSID SSID, -s SSID  specify target SSID

  Specify repair techniques

  --all, -a             perform all repair techniques
  -1                    Check for EAPOL Message 1 with PMKID and adds missing Beacon frame
  -2                    Check for EAPOL Message 1 + Message 2 sequence and adds missing Beacon frame
  -3                    Check for EAPOL Message 2 + Message 3 sequence and adds missing Beacon & EAPOL Message 1 frames
                                                                                                                                                                                                                                            
```

# Example
## Repair Technique 1
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ python3 rehandshake.py -f /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap -s fakecorp -1
[+] Number of frames read from '/home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap': 24585
[-]   Number of Beacon frames found: 1
[-]   Number of EAPOL frames found: 5
[-]     Number of EAPOL Message 1 frames found: 1
[-]     Number of EAPOL Message 2 frames found: 2
[-]     Number of EAPOL Message 3 frames found: 1
[-]     Number of EAPOL Message 4 frames found: 1
[-]
[+] Evaulation Repair Techniques
[-]   Candiate Technique 1: Checking for EAPOL Message 1 Frames for PMKID
[-]     Found a PMKID!
[-]     Number of PMKID Candiates found: 1
[-]     Checking for relevant candiate Beacon frame
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.pcap
[-]   Candiate Technique 1: Success
                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ /opt/hcxtools/hcxpcapngtool /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.pcap -o /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.22000
hcxpcapngtool 6.2.4-21-g54def30 reading from original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.pcap...

summary capture file
--------------------
file name................................: original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.pcap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
timestamp minimum (GMT)..................: 02.10.2021 09:24:14
timestamp maximum (GMT)..................: 02.10.2021 09:29:18
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianess (capture system)...............: little endian
packets inside...........................: 2
frames with correct FCS..................: 2
BEACON (total)...........................: 1
EAPOL messages (total)...................: 1
EAPOL RSN messages.......................: 1
ESSID (total unique).....................: 1
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 1
PMKID (total)............................: 1
PMKID (best).............................: 1
PMKID written to combi hash file.........: 1

Warning: missing frames!
This dump file does not contain undirected proberequest frames.
An undirected proberequest may contain information about the PSK.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain important frames like
authentication, association or reassociation.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain enough EAPOL M1 frames.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it impossible to calculate nonce-error-correction values.


session summary
---------------
processed cap files...................: 1

                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ echo "vr9n9yr2hgva" |hashcat -m 22000 /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.22000 --quiet
3579e3473282a5d7faaff3701cd3a985:7a655927f40c:1e1c7a841b56:fakecorp:vr9n9yr2hgva
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-PBKDF2-PMKID+EAPOL
Hash.Target......: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.22000
Time.Started.....: Sat Oct  9 03:26:55 2021 (0 secs)
Time.Estimated...: Sat Oct  9 03:26:55 2021 (0 secs)
Guess.Base.......: Pipe
Speed.#1.........:       84 H/s (2.09ms) @ Accel:32 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1
Rejected.........: 0
Restore.Point....: 0
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: vr9n9yr2hgva -> vr9n9yr2hgva

```

## Repair Technique 2
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ python3 rehandshake.py -f /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap -s fakecorp -2
[+] Number of frames read from '/home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap': 24585
[-]   Number of Beacon frames found: 1
[-]   Number of EAPOL frames found: 5
[-]     Number of EAPOL Message 1 frames found: 1
[-]     Number of EAPOL Message 2 frames found: 2
[-]     Number of EAPOL Message 3 frames found: 1
[-]     Number of EAPOL Message 4 frames found: 1
[-]
[+] Evaulation Repair Techniques
[-]
[-]   Candiate Technique 2: Checking for EAPOL Message 1+Message 2 Pair Sequence
[-]     Removing duplicate EAPOL Message 1 frames...
[-]     Found new EAPOL Message 1, adding to list...
[-]     Removing duplicate EAPOL Message 2 frames...
[-]     Found new EAPOL Message 2, adding to list...
[-]     Duplicate EAPOL Message 2 found, skipping...
[-]     Checking for EAPOL Message 1 and Message 2 pairs
[-]     Pair found!
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.pcap
[-]   Candiate Technique 2: Success
[-]
[-]
[+] Evaulation Repair Techniques finished!
                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ /opt/hcxtools/hcxpcapngtool /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.pcap -o /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.22000
hcxpcapngtool 6.2.4-21-g54def30 reading from original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.pcap...

summary capture file
--------------------
file name................................: original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.pcap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
timestamp minimum (GMT)..................: 02.10.2021 09:24:14
timestamp maximum (GMT)..................: 02.10.2021 09:29:18
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianess (capture system)...............: little endian
packets inside...........................: 3
frames with correct FCS..................: 3
BEACON (total)...........................: 1
EAPOL messages (total)...................: 2
EAPOL RSN messages.......................: 2
ESSID (total unique).....................: 1
EAPOLTIME gap (measured maximum usec)....: 3160
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 1
EAPOL M2 messages (total)................: 1
EAPOL pairs (total)......................: 1
EAPOL pairs (best).......................: 1
EAPOL pairs written to combi hash file...: 1 (RC checked)
EAPOL M12E2 (challenge)..................: 1
PMKID (total)............................: 1
PMKID (best).............................: 1
PMKID written to combi hash file.........: 1

Warning: missing frames!
This dump file does not contain undirected proberequest frames.
An undirected proberequest may contain information about the PSK.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain important frames like
authentication, association or reassociation.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain enough EAPOL M1 frames.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it impossible to calculate nonce-error-correction values.


session summary
---------------
processed cap files...................: 1

                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ echo "vr9n9yr2hgva" |hashcat -m 22000 /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.22000 --quiet
3579e3473282a5d7faaff3701cd3a985:7a655927f40c:1e1c7a841b56:fakecorp:vr9n9yr2hgva
6280c2662c1d31c5aeef2ff7489b7296:7a655927f40c:1e1c7a841b56:fakecorp:vr9n9yr2hgva
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-PBKDF2-PMKID+EAPOL
Hash.Target......: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.22000
Time.Started.....: Sat Oct  9 03:30:26 2021 (0 secs)
Time.Estimated...: Sat Oct  9 03:30:26 2021 (0 secs)
Guess.Base.......: Pipe
Speed.#1.........:       91 H/s (0.90ms) @ Accel:64 Loops:512 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests
Progress.........: 1
Rejected.........: 0
Restore.Point....: 0
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1-3
Candidates.#1....: vr9n9yr2hgva -> vr9n9yr2hgva
 
```
*Note:* The PMKID (`3579e3473282a5d7faaff3701cd3a985:7a655927f40c:1e1c7a841b56`) in the EAPOL Message 1 frame has also been re-extracted in the example by `hcxpcapngtool`, and subsequentially the PSK has been recovered by `hashcat`. 

## Repair Technique 3
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ python3 rehandshake.py -f /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap -s fakecorp -3
[+] Number of frames read from '/home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap': 24585
[-]   Number of Beacon frames found: 1
[-]   Number of EAPOL frames found: 5
[-]     Number of EAPOL Message 1 frames found: 1
[-]     Number of EAPOL Message 2 frames found: 2
[-]     Number of EAPOL Message 3 frames found: 1
[-]     Number of EAPOL Message 4 frames found: 1
[-]
[+] Evaulation Repair Techniques
[-]
[-]
[-]   Candiate Technique 3: Checking for EAPOL Message 2+Message 3 Pair Sequence
[-]     Removing duplicate EAPOL Message 2 frames...
[-]     Found new EAPOL Message 2, adding to list...
[-]     Duplicate EAPOL Message 2 found, skipping...
[-]     Removing duplicate EAPOL Message 3 frames...
[-]     Found new EAPOL Message 3, adding to list...
[-]     Checking for EAPOL Message 2 and Message 3 pairs
[-]     Pair found!
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.pcap
[-]   Candiate Technique 3: Success
[-]
[+] Evaulation Repair Techniques finished!
                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ /opt/hcxtools/hcxpcapngtool /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.pcap -o /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.22000
hcxpcapngtool 6.2.4-21-g54def30 reading from original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.pcap...

summary capture file
--------------------
file name................................: original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.pcap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
timestamp minimum (GMT)..................: 02.10.2021 09:24:14
timestamp maximum (GMT)..................: 09.10.2021 03:39:34
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianess (capture system)...............: little endian
packets inside...........................: 4
frames with correct FCS..................: 3
BEACON (total)...........................: 1
EAPOL messages (total)...................: 3
EAPOL RSN messages.......................: 3
ESSID (total unique).....................: 1
EAPOLTIME gap (measured maximum usec)....: 7805
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 1
EAPOL M2 messages (total)................: 1
EAPOL M3 messages (total)................: 1
EAPOL pairs (total)......................: 1
EAPOL pairs (best).......................: 1
EAPOL pairs written to combi hash file...: 1 (RC checked)
EAPOL M32E2 (authorized).................: 1

Warning: out of sequence timestamps!
This dump file contains frames with out of sequence timestamps.
That is a bug of the capturing tool.

Warning: missing frames!
This dump file does not contain undirected proberequest frames.
An undirected proberequest may contain information about the PSK.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain important frames like
authentication, association or reassociation.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.

Warning: missing frames!
This dump file does not contain enough EAPOL M1 frames.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it impossible to calculate nonce-error-correction values.


session summary
---------------
processed cap files...................: 1

                                                                                                                                                                                                                                            
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ echo "vr9n9yr2hgva" |hashcat -m 22000 /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.22000 --quiet
6280c2662c1d31c5aeef2ff7489b7296:7a655927f40c:1e1c7a841b56:fakecorp:vr9n9yr2hgva
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-PBKDF2-PMKID+EAPOL
Hash.Target......: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.22000
Time.Started.....: Sat Oct  9 03:40:38 2021 (0 secs)
Time.Estimated...: Sat Oct  9 03:40:38 2021 (0 secs)
Guess.Base.......: Pipe
Speed.#1.........:       85 H/s (1.07ms) @ Accel:64 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1
Rejected.........: 0
Restore.Point....: 0
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: vr9n9yr2hgva -> vr9n9yr2hgva
 
```

## All Repair Technique Checks
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/development/wireless/rehandshake]
└─$ python3 rehandshake.py -f /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap -s fakecorp -a
[+] Number of frames read from '/home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva.pcap': 24585
[-]   Number of Beacon frames found: 1
[-]   Number of EAPOL frames found: 5
[-]     Number of EAPOL Message 1 frames found: 1
[-]     Number of EAPOL Message 2 frames found: 2
[-]     Number of EAPOL Message 3 frames found: 1
[-]     Number of EAPOL Message 4 frames found: 1
[-]
[+] Evaulation Repair Techniques
[-]   Candiate Technique 1: Checking for EAPOL Message 1 Frames for PMKID
[-]     Found a PMKID!
[-]     Number of PMKID Candiates found: 1
[-]     Checking for relevant candiate Beacon frame
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_1.pcap
[-]   Candiate Technique 1: Success
[-]
[-]   Candiate Technique 2: Checking for EAPOL Message 1+Message 2 Pair Sequence
[-]     Removing duplicate EAPOL Message 1 frames...
[-]     Found new EAPOL Message 1, adding to list...
[-]     Removing duplicate EAPOL Message 2 frames...
[-]     Found new EAPOL Message 2, adding to list...
[-]     Duplicate EAPOL Message 2 found, skipping...
[-]     Checking for EAPOL Message 1 and Message 2 pairs
[-]     Pair found!
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_2.pcap
[-]   Candiate Technique 2: Success
[-]
[-]   Candiate Technique 3: Checking for EAPOL Message 2+Message 3 Pair Sequence
[-]     Removing duplicate EAPOL Message 2 frames...
[-]     Found new EAPOL Message 2, adding to list...
[-]     Duplicate EAPOL Message 2 found, skipping...
[-]     Removing duplicate EAPOL Message 3 frames...
[-]     Found new EAPOL Message 3, adding to list...
[-]     Checking for EAPOL Message 2 and Message 3 pairs
[-]     Pair found!
[-]     candiate Beacon frame found, skipping...
[-]     Creating candiate PCAP file: /home/vagrant/development/wireless/cracking_broken_psks/original_full_fakecorp_vr9n9yr2hgva_repaired_candiate_3.pcap
[-]   Candiate Technique 3: Success
[-]
[+] Evaulation Repair Techniques finished!
 
```
