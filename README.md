# Source-Port-0-Observation
My observation of an attack on my honeypots for SANS BACS internship program
## Synopsis
IP 79.124.62.230 was noted executing anomalous activity on the honeypot. There have been around 25,299 connections from this single IP address alone and all the connections had a source port of 0 targeting multiple destination ports on the honeypot.

![image](https://github.com/user-attachments/assets/34d429b9-33b7-4c5c-b047-8a7de1544031)
![image](https://github.com/user-attachments/assets/78d25795-289d-4b8c-8394-c6bb83b37306)

<sub>*Screen capture of ELK stack*</sub>




This type of activity is synonymous with port scanning. many connections in a short amount of time is already indicator of an attack, what is even more suspicious is that the attacker conducted this port scan using source port 0. Port 0 as a destination or Source port should never be used for legitimate traffic and serves as a Reserved port for IANA [[1]](https://www.rfc-editor.org/rfc/rfc6335.html#page-12).
To confirm my suspicions of a port scan taking place, I looked at the packet captures of the honeypot looking at the traffic from IP 79.124.62.230 and the below screenshot confirms my theory of a port scan, more specifically a SYN Scan. 
![image](https://github.com/user-attachments/assets/637da524-decf-45d4-970f-eb06f732f634)

<sub>*Screen capture of Wireshark depicting Attackers SYN Scan*</sub>





As you can see from the packet capture IP 79.124.62.230 is sending a lot of SYN packets over various ports looking for response from the honeypot. After going through the packet captures, the honeypot wasn’t listening on any of the destination ports interrogated so there was no response back to the attacker. The timing between packets are seemingly random, from the above screenshot the timing in between range from 2-30 seconds, this could be due to any latency from the attackers location to my honeypot, other packets the honeypot needs to process, or there could evasion techniques at hand. At first my guess would be that the attacker is using nmap to accomplish these scans but investigation leads me to believe that is not the case and the attacker could’ve potentially coded their own scanner. Nmap by default uses ephemeral ports as a source port to conduct scans (more specifically leaves up to the OS) [[2]](https://nmap.org/book/firewall-subversion.html). Nmap does have the option to use the -g <port #> argument to send packets with a specific source port [[2]](https://nmap.org/book/firewall-subversion.html), but I find it hard to believe an attacker would purposefully use source port 0 as it raises a bunch of red flags for SOC analysts or anyone monitoring the network. Another reason I believe the attacker is using their own scanner is that the window size is set to 1025. Below is a screen shot of me conducting an Nmap scan on my local network.

![image](https://github.com/user-attachments/assets/59d0abb7-0de3-4088-89d4-90f3a71d698c)

 <sub>*Screen capture of Wireshark depicting Nmap SYN. Scan Note: I used -g 0 argument to conduct this scan*</sub>

Nmap uses 1024 for the window size as depicted in the screen shot above. 
Below is a screen shot of conducting an Nmap SYN scan with out the -g argument to show what a normal Nmap scan looks like for comparison.

![image](https://github.com/user-attachments/assets/f532cf91-4e0d-497e-8339-761a2f32ef76) 

<sub>*Screen capture of Wireshark depicting default Nmap SYN Scan*</sub>

While looking through the packets I also noticed that the attacker’s scanner uses a TTL (Time-to-Live) of 240 for every single packet. This is mostly likely to ensure the packets reach my honeypot and don’t get dropped.

![image](https://github.com/user-attachments/assets/c53870d1-3d8e-42e9-ba5c-064d154a91be)

<sub>*Screen capture of Wireshark Statistics depicting the attacker’s scans and their TTL’s*</sub>

Nmap on the other hand uses random TTL’s when conducting their scans

![image](https://github.com/user-attachments/assets/ef0b36af-49eb-4736-93b1-33df758e8003)

<sub>*Screen capture of Wireshark Statistics depicting Nmap’s scans and their TTL’s*</sub>

I believe with this evidence, at the very least the attacker isn’t using Nmap to conduct these scans. There are a couple of other scanners such as masscan [[3]](https://github.com/robertdavidgraham/masscan), but I’m leaning towards this potentially being a scanner created by the attacker.

## Vulnerabilities Exploited/ Techniques
This attacker hasn’t been seen exploiting any vulnerabilities in the system but just scanning the system to potentially enumerate any open/listening ports on the system. I believe the attacker is also attempting to evade IDS by crafting their own scanner than using a well known tool such as nmap/zenmap.

This type of activity is consistent with MITRE ATT&CK Technique T1046 Network Service Discovery [[4]](https://attack.mitre.org/techniques/T1046/)

## Goal of the Attack
The goal of this attack is to enumerate and discover any exposed ports to potentially exploit. With certain scanners you can potentially enumerate the specific OS and version and use that information to attack a specific vulnerability. I noticed that the attacker didn’t scan for most common ports (i.e 22,23,80,443,445), The attacker was probably looking for a not so well known or ephemeral port to setup a back door using that port since it’s less likely to be monitored.

## Information About the Attacker
IP 79.124.62.230 originates from Bulgaria and owned by the ISP Tamatiya EOOD. IP was first reported to ISC Nov 25 2024 and last seen March 16 2025 [[5]](https://isc.sans.edu/ipinfo/79.124.62.230).

This attacker has been seen multiple times on only one of my honeypots doing the same type of port scans at around the same time almost every day.
![image](https://github.com/user-attachments/assets/264ba5ea-eb58-4f4b-b4a1-1770cdfd0f7e)
<sub>*Screen Capture of SIEM depicting a pattern of the attackers activity*</sub>
VirustotalIP gives this a community score of -4 with other people commenting how they’ve seen this IP scanning their networks with source port 0 and getting around firewalls [[6]](https://www.virustotal.com/gui/ip-address/79.124.62.230/community).
## How to Protect Your Network Against Scanning
- Ensure that any unnecessary ports/services are closed and turned off
- Use IDS/IPS to detect/prevent service scans
- Ensure Proper segmentation of critical assests
- Keep All systems up to date
- Monitor Network for unusal activity
## References
[1] https://www.rfc-editor.org/rfc/rfc6335.html#page-12  
[2] https://nmap.org/book/firewall-subversion.html  
[3] https://github.com/robertdavidgraham/masscan  
[4] https://attack.mitre.org/techniques/T1046/  
[5] https://isc.sans.edu/ipinfo/79.124.62.230  
[6] https://www.virustotal.com/gui/ip-address/79.124.62.230/community  
