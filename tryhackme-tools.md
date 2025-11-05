|Tool|Category|Description|Example|
|---|---|---|---|
|whois|Recon|Domain registration lookup|whois example.com|
|dig|Recon|DNS queries and records lookup|dig +short example.com|
|amass|Recon|DNS/subdomain enumeration and mapping|amass enum -d example.com|
|crt.sh|Recon|Certificate transparency / subdomain discovery|(web) https://crt.sh/|
|sublist3r|Recon|Quick subdomain discovery|sublist3r -d example.com|
|theHarvester|Recon|Email/subdomain harvesting from public sources|theHarvester -d example.com -b all|
|Shodan|OSINT|Internet-connected device search engine|(web/API) https://shodan.io/|
|Censys|OSINT|Internet-wide host and certificate search|(web/API) https://censys.io/|
|nmap|Network|Port & service scanner|nmap -sC -sV -p- target|
|masscan|Network|Very fast large-range port scanner|masscan -p80 10.0.0.0/8|
|rustscan|Network|Fast scanner that pipelines to nmap|rustscan -a target -- -A|
|arp-scan|Network|Local network discovery|arp-scan -l|
|gobuster|Web|Directory/subdomain brute-forcing|gobuster dir -u http://site -w wordlist.txt|
|ffuf|Web|Fast web fuzzer for directories/params|ffuf -u http://site/FUZZ -w wordlist.txt|
|dirb|Web|Web directory brute-force|dirb http://site wordlist.txt|
|feroxbuster|Web|Recursive web discovery and fuzzing|feroxbuster -u http://site -w wordlist.txt|
|sqlmap|Web|Automated SQL injection testing/exploitation|sqlmap -u "http://site?id=1" --batch|
|burpsuite|Web|Web proxy/intercept and manual testing|Start Burp and set browser proxy|
|wpscan|Web|WordPress vulnerability scanner|wpscan --url http://site|
|smbclient|SMB|SMB client for accessing shares|smbclient -L //target|
|smbmap|SMB|Map & enumerate SMB shares|smbmap -H target|
|enum4linux|SMB|Windows/SMB enumeration script|enum4linux -a target|
|impacket|SMB/Windows|Python tools for SMB auth & exec (wmiexec/psexec)|python3 wmiexec.py user:pass@target|
|Responder|SMB/NetBIOS|LLMNR/NBNS poisoner to capture creds|sudo responder -I eth0|
|crackmapexec|Post-exploit|Post-exploitation & lateral movement helper|crackmapexec smb target -u user -p pass|
|metasploit|Exploitation|Exploit framework and payloads|msfconsole|
|searchsploit|Exploitation|Search Exploit-DB from CLI|searchsploit apache 2.4|
|nikto|Web|Web server vulnerability scanner|nikto -h http://site|
|john|Cracking|Password/hash cracking (wordlist mode)|john --wordlist=rockyou.txt hash.txt|
|hashcat|Cracking|GPU-accelerated hash cracking|hashcat -m 1000 hash.txt rockyou.txt|
|hydra|Cracking|Online service brute-forcing (ssh/http)|hydra -l user -P pass.txt ssh://target|
|patator|Cracking|Flexible brute-forcer for many protocols|patator ssh_login host=target user=FILE0 password=FILE1 0=userlist 1=passlist|
|mimikatz|Windows|Extract Windows credentials (post-exploit)|Run on Windows host (authorized lab only)|
|nc|Shells|Netcat — listeners & reverse shells|nc -lvnp 4444|
|socat|Tunneling|Advanced socket proxying and relays|socat TCP-LISTEN:4444,reuseaddr EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane|
|ssh|Tunneling|Port forwarding and reverse tunnels|ssh -R 80:localhost:8080 user@host|
|ngrok|Tunneling|Expose local services to internet (use carefully)|ngrok http 8080|
|linpeas|PrivEsc|Linux privilege escalation enumeration|./linpeas.sh|
|winPEAS|PrivEsc|Windows privilege escalation checks|Run winPEAS on Windows host|
|pspy|PrivEsc|Monitor process activity on Linux|./pspy64|
|tcpdump|Forensics|Capture packets from CLI|tcpdump -i eth0 -w capture.pcap|
|wireshark|Forensics|GUI packet analysis|Open capture.pcap in Wireshark|
|volatility|Forensics|Memory forensics and analysis|volatility -f memdump imageinfo|
|python3|Scripting|Scripting and exploitation helper|python3 -c 'print(\"hi\")'|
|pwntools|Scripting|CTF exploitation library in Python|Use pwntools for remote pwn scripts|
|awk/sed/jq|Helpers|Text and JSON processing|jq . data.json|
|curl|Helpers|HTTP requests and quick checks|curl -I http://site|
