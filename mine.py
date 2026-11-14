#!/usr/bin/env python3
"""Count how often each candidate resource is mentioned on Hacker News (Algolia API,
no key needed) and on Stack Exchange security Q&A sites and write data.js for index.html.  Usage: python3 mine.py [--check-links]

Candidates are hand-picked; HN decides whether they stay (see MIN_* below) and how they rank.
"""
import gzip, json, sys, time, urllib.parse, urllib.request, collections, pathlib

MIN_MENTIONS, MIN_YEARS = 5, 3          # "repeatedly recommended over the years"
YEARS = range(2007, time.gmtime().tm_year + 1)
HERE = pathlib.Path(__file__).parent
CACHE_F = HERE / ".cache.json"
CACHE = json.loads(CACHE_F.read_text()) if CACHE_F.exists() else {}

C, W, AD, MA, RE, CL, F = ("Cryptography", "Web Pentest", "Active Directory", "Malware Analysis",
                           "Reverse Engineering", "Cloud & DevSecOps", "Foundations & CTFs")
# (category, type, name, url, description, [HN search queries])
# Queries use Algolia syntax: "quoted phrase" is exact, extra bare words are AND-ed.
CANDIDATES = [
 # ---------------- Cryptography
 (C, "Lab", "Cryptopals Crypto Challenges", "https://cryptopals.com", "Eight sets of exercises where you implement and then break real-world crypto: padding oracles, CBC bit-flipping, RSA and more.", ['"cryptopals"']),
 (C, "Lab", "CryptoHack", "https://cryptohack.org", "Gamified platform of cryptography challenges, from modular arithmetic to elliptic curves and lattices.", ['"cryptohack"']),
 (C, "Course", "Cryptography I (Dan Boneh, Stanford)", "https://www.coursera.org/learn/crypto", "Stanford's online cryptography course: stream and block ciphers, MACs, authenticated encryption, public-key basics.", ['"coursera.org/learn/crypto"', '"crypto-class.org"', '"Cryptography I" Boneh']),
 (C, "Book", "A Graduate Course in Applied Cryptography", "https://toc.cryptobook.us", "Boneh and Shoup's free, rigorous textbook on applied cryptography.", ['"cryptobook.us"', '"Graduate Course in Applied Cryptography"']),
 (C, "Book", "Crypto 101", "https://www.crypto101.io", "Free introductory cryptography book for programmers.", ['"crypto101"']),
 (C, "Book", "Serious Cryptography", "https://nostarch.com/seriouscrypto", "Jean-Philippe Aumasson's practical introduction to modern encryption.", ['"Serious Cryptography"']),
 (C, "Book", "Real-World Cryptography", "https://www.manning.com/books/real-world-cryptography", "David Wong's book on the cryptography actually deployed in protocols and products.", ['"Real-World Cryptography" Wong', '"manning.com/books/real-world-cryptography"']),
 (C, "Book", "Cryptography Engineering", "https://www.schneier.com/books/cryptography-engineering/", "Ferguson, Schneier and Kohno on designing and implementing cryptographic systems.", ['"Cryptography Engineering" Schneier', '"Cryptography Engineering" Ferguson']),
 (C, "Book", "The Joy of Cryptography", "https://joyofcryptography.com", "Mike Rosulek's free undergraduate textbook on provable security.", ['"joyofcryptography"', '"Joy of Cryptography"']),
 (C, "Book", "Handbook of Applied Cryptography", "https://cacr.uwaterloo.ca/hac/", "Menezes, van Oorschot and Vanstone's classic reference, free online.", ['"Handbook of Applied Cryptography"']),
 (C, "Book", "Introduction to Modern Cryptography", "https://www.cs.umd.edu/~jkatz/imc.html", "Katz and Lindell's standard university textbook.", ['"Introduction to Modern Cryptography" Katz', '"Introduction to Modern Cryptography" Lindell']),
 (C, "Book", "Understanding Cryptography", "https://www.crypto-textbook.com", "Paar and Pelzl's textbook, with Christof Paar's full lecture series on video.", ['"crypto-textbook.com"', '"Understanding Cryptography" Paar']),
 (C, "Book", "Practical Cryptography for Developers", "https://cryptobook.nakov.com", "Svetlin Nakov's free developer-oriented book with code examples.", ['"cryptobook.nakov.com"', '"Practical Cryptography for Developers"']),
 (C, "Reading", "Cryptographic Right Answers", "https://www.latacora.com/blog/2018/04/03/cryptographic-right-answers/", "Latacora's opinionated list of which primitive to pick for each job.", ['"Cryptographic Right Answers"']),
 (C, "Reading", "A Few Thoughts on Cryptographic Engineering", "https://blog.cryptographyengineering.com", "Matthew Green's blog explaining crypto attacks and protocol design.", ['"blog.cryptographyengineering.com"']),
 (C, "Reading", "The Illustrated TLS Connection", "https://tls13.xargs.org", "Every byte of a TLS handshake explained and reproduced.", ['"tls13.xargs.org"', '"tls12.xargs.org"', '"tls.ulfheim.net"', '"Illustrated TLS"']),
 (C, "Reading", "Dhole Moments (Soatok)", "https://soatok.blog", "Soatok's blog on applied cryptography and how to learn it.", ['"soatok.blog"']),
 # ---------------- Web Pentest
 (W, "Lab", "PortSwigger Web Security Academy", "https://portswigger.net/web-security", "Free web security training with interactive labs for every major vulnerability class.", ['"portswigger.net/web-security"', '"Web Security Academy"']),
 (W, "Lab", "OWASP Juice Shop", "https://owasp.org/www-project-juice-shop/", "Deliberately insecure modern web shop with a scoreboard of hacking challenges.", ['"juice shop" owasp', '"bkimminich"']),
 (W, "Lab", "DVWA (Damn Vulnerable Web Application)", "https://github.com/digininja/DVWA", "PHP/MySQL app that is vulnerable on purpose, with adjustable difficulty.", ['"DVWA"']),
 (W, "Lab", "OWASP WebGoat", "https://owasp.org/www-project-webgoat/", "Deliberately insecure Java application with guided lessons.", ['"WebGoat"']),
 (W, "Lab", "Google Gruyere", "https://google-gruyere.appspot.com", "Google's codelab on web application exploits and defences, using a small cheesy app.", ['"google-gruyere"', '"Google Gruyere"']),
 (W, "Lab", "XSS Game", "https://xss-game.appspot.com", "Google's cross-site scripting challenge levels.", ['"xss-game.appspot.com"']),
 (W, "Lab", "Hacker101", "https://www.hacker101.com", "HackerOne's free web security video lessons and CTF.", ['"hacker101"']),
 (W, "Lab", "PentesterLab", "https://pentesterlab.com", "Exercises teaching web penetration testing on real vulnerabilities.", ['"pentesterlab"']),
 (W, "Lab", "OverTheWire: Natas", "https://overthewire.org/wargames/natas/", "Wargame teaching the basics of server-side web security.", ['"natas" overthewire']),
 (W, "Lab", "Hacksplaining", "https://www.hacksplaining.com", "Interactive lessons demonstrating common web vulnerabilities.", ['"hacksplaining"']),
 (W, "Course", "Stanford CS 253: Web Security", "https://web.stanford.edu/class/cs253/", "Feross Aboukhadijeh's Stanford web security course; slides and lectures online.", ['"cs253" stanford', '"web.stanford.edu/class/cs253"']),
 (W, "Book", "The Web Application Hacker's Handbook", "https://portswigger.net/web-security/web-application-hackers-handbook", "Stuttard and Pinto's long-standard book on finding and exploiting web flaws.", ['"Web Application Hacker\'s Handbook"', '"Web Application Hackers Handbook"']),
 (W, "Book", "The Tangled Web", "https://nostarch.com/tangledweb", "Michal Zalewski's guide to the browser security model.", ['"Tangled Web" Zalewski', '"nostarch.com/tangledweb"']),
 (W, "Book", "Real-World Bug Hunting", "https://nostarch.com/bughunting", "Peter Yaworski's field guide built on real bug bounty reports (grew out of Web Hacking 101).", ['"Real-World Bug Hunting"', '"Web Hacking 101"']),
 (W, "Reading", "OWASP Top 10", "https://owasp.org/www-project-top-ten/", "Awareness document listing the most critical web application security risks.", ['"OWASP Top 10"', '"OWASP Top Ten"']),
 (W, "Reading", "OWASP Cheat Sheet Series", "https://cheatsheetseries.owasp.org", "Concise defensive guidance on specific application security topics.", ['"cheatsheetseries.owasp.org"', '"OWASP Cheat Sheet"', '"OWASP Cheat Sheets"']),
 (W, "Reading", "OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/", "Comprehensive methodology for testing web applications.", ['"Web Security Testing Guide"', '"OWASP Testing Guide"']),
 (W, "Reading", "HackTricks", "https://book.hacktricks.wiki", "Carlos Polop's wiki of pentesting techniques and checklists.", ['"hacktricks"']),
 (W, "Reading", "HackerOne Hacktivity", "https://hackerone.com/hacktivity", "Feed of publicly disclosed bug bounty reports.", ['"hackerone.com/hacktivity"']),
 (W, "Repo", "PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings", "Payloads and bypasses for web application security testing.", ['"PayloadsAllTheThings"']),
 (W, "Repo", "SecLists", "https://github.com/danielmiessler/SecLists", "Wordlists for security assessments: usernames, passwords, URLs, fuzzing payloads.", ['"danielmiessler/SecLists"', '"SecLists" Miessler']),
 (W, "Tool", "Burp Suite", "https://portswigger.net/burp", "Intercepting proxy and web vulnerability testing toolkit.", ['"Burp Suite"', '"burpsuite"']),
 (W, "Tool", "ZAP (Zed Attack Proxy)", "https://www.zaproxy.org", "Open-source web app scanner and intercepting proxy.", ['"zaproxy"', '"OWASP ZAP"', '"Zed Attack Proxy"']),
 (W, "Tool", "mitmproxy", "https://mitmproxy.org", "Open-source interactive HTTPS proxy.", ['"mitmproxy"']),
 (W, "Tool", "sqlmap", "https://sqlmap.org", "Automatic SQL injection detection and exploitation tool.", ['"sqlmap"']),
 (W, "Tool", "Nuclei", "https://github.com/projectdiscovery/nuclei", "Template-based vulnerability scanner.", ['"projectdiscovery/nuclei"', '"nuclei" projectdiscovery']),
 # ---------------- Active Directory
 (AD, "Tool", "BloodHound", "https://github.com/SpecterOps/BloodHound", "Graphs Active Directory relationships to reveal attack paths.", ['"bloodhound" "active directory"', '"BloodHoundAD"', '"SpecterOps/BloodHound"']),
 (AD, "Tool", "Impacket", "https://github.com/fortra/impacket", "Python classes and example scripts for Windows network protocols (SMB, Kerberos, MSRPC).", ['"impacket"']),
 (AD, "Tool", "Mimikatz", "https://github.com/gentilkiwi/mimikatz", "Benjamin Delpy's tool for extracting Windows credentials and Kerberos tickets.", ['"mimikatz"']),
 (AD, "Tool", "Responder", "https://github.com/lgandx/Responder", "LLMNR/NBT-NS/mDNS poisoner for capturing network authentication.", ['"responder" LLMNR', '"lgandx/Responder"', '"SpiderLabs/Responder"']),
 (AD, "Tool", "Rubeus", "https://github.com/GhostPack/Rubeus", "C# toolset for Kerberos interaction and abuse.", ['"Rubeus"']),
 (AD, "Tool", "NetExec (formerly CrackMapExec)", "https://github.com/Pennyw0rth/NetExec", "Network service exploitation tool for assessing Windows/AD networks.", ['"crackmapexec"', '"netexec"']),
 (AD, "Tool", "PowerSploit / PowerView", "https://github.com/PowerShellMafia/PowerSploit", "PowerShell post-exploitation modules, including PowerView for AD reconnaissance (archived).", ['"PowerSploit"', '"PowerView" "active directory"']),
 (AD, "Tool", "PingCastle", "https://www.pingcastle.com", "Active Directory security audit tool.", ['"pingcastle"']),
 (AD, "Tool", "hashcat", "https://hashcat.net/hashcat/", "Password recovery tool, used for cracking NTLM hashes and Kerberos tickets.", ['"hashcat"']),
 (AD, "Lab", "GOAD (Game of Active Directory)", "https://github.com/Orange-Cyberdefense/GOAD", "Vulnerable multi-domain Active Directory lab you deploy yourself.", ['"Orange-Cyberdefense/GOAD"', '"Game of Active Directory"']),
 (AD, "Lab", "Vulnerable-AD", "https://github.com/safebuffer/vulnerable-AD", "Script that makes a test domain controller vulnerable to common AD attacks.", ['"vulnerable-AD"']),
 (AD, "Lab", "DetectionLab", "https://github.com/clong/DetectionLab", "Automated Windows domain lab pre-loaded with security tooling and logging (no longer maintained).", ['"DetectionLab"']),
 (AD, "Reading", "Active Directory Security (adsecurity.org)", "https://adsecurity.org", "Sean Metcalf's blog on AD attacks and defences.", ['"adsecurity.org"']),
 (AD, "Reading", "Red Team Notes (ired.team)", "https://www.ired.team", "Notes on red teaming and Active Directory techniques.", ['"ired.team"']),
 (AD, "Reading", "The Hacker Recipes", "https://www.thehacker.recipes", "Guide to Active Directory and network attack techniques.", ['"thehacker.recipes"']),
 (AD, "Reading", "harmj0y's blog", "https://blog.harmj0y.net", "Will Schroeder's posts on Kerberos and Active Directory abuse.", ['"harmj0y"']),
 (AD, "Reading", "dirkjanm.io", "https://dirkjanm.io", "Dirk-jan Mollema's research on Active Directory and Entra ID.", ['"dirkjanm"']),
 (AD, "Reading", "Certified Pre-Owned", "https://posts.specterops.io/certified-pre-owned-d95910965cd2", "SpecterOps research on abusing Active Directory Certificate Services.", ['"Certified Pre-Owned" "Active Directory"', '"Certified Pre-Owned" specterops', '"certified-pre-owned-d95910965cd2"']),
 (AD, "Reading", "Attacking Active Directory: 0 to 0.9", "https://zer1t0.gitlab.io/posts/attacking_ad/", "Long-form walkthrough of AD concepts and attacks.", ['"zer1t0"', '"attacking_ad"']),
 (AD, "Reading", "Designing an Authentication System: a Dialogue in Four Scenes", "https://web.mit.edu/kerberos/dialogue.html", "MIT's classic play explaining why Kerberos works the way it does.", ['"kerberos/dialogue.html"', '"Dialogue in Four Scenes"']),
 # ---------------- Malware Analysis
 (MA, "Book", "Practical Malware Analysis", "https://nostarch.com/malware", "Sikorski and Honig's hands-on book with lab binaries.", ['"Practical Malware Analysis"']),
 (MA, "Book", "Malware Analyst's Cookbook", "https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD%3A+Tools+and+Techniques+for+Fighting+Malicious+Code-p-9780470613030", "Recipes and tools for analysing malicious code.", ['"Malware Analyst\'s Cookbook"', '"Malware Analysts Cookbook"']),
 (MA, "Course", "Malware Unicorn: Reverse Engineering 101", "https://malwareunicorn.org/workshops/re101.html", "Amanda Rousseau's free workshops on reversing Windows malware.", ['"malwareunicorn"']),
 (MA, "Video", "OALabs", "https://www.youtube.com/@OALABS", "Malware reverse engineering tutorials on YouTube.", ['"OALabs"', '"Open Analysis Live"']),
 (MA, "Reading", "MalwareTech", "https://malwaretech.com", "Marcus Hutchins' blog on malware analysis and vulnerability research.", ['"malwaretech.com"']),
 (MA, "Lab", "Malware-Traffic-Analysis.net", "https://www.malware-traffic-analysis.net", "Pcaps of real infections and traffic analysis exercises.", ['"malware-traffic-analysis.net"']),
 (MA, "Repo", "vx-underground", "https://vx-underground.org", "Large collection of malware samples, source code and papers.", ['"vx-underground"', '"vxunderground"']),
 (MA, "Repo", "theZoo", "https://github.com/ytisf/theZoo", "Repository of live malware samples for analysis.", ['"ytisf/theZoo"', '"theZoo" malware']),
 (MA, "Repo", "MalwareBazaar", "https://bazaar.abuse.ch", "abuse.ch's malware sample sharing platform.", ['"bazaar.abuse.ch"', '"MalwareBazaar"']),
 (MA, "Tool", "VirusTotal", "https://www.virustotal.com", "Scans files and URLs with many antivirus engines.", ['"virustotal"']),
 (MA, "Tool", "ANY.RUN", "https://any.run", "Interactive online malware sandbox.", ['"any.run" malware', '"app.any.run"']),
 (MA, "Tool", "Hybrid Analysis", "https://www.hybrid-analysis.com", "Free automated malware analysis service.", ['"hybrid-analysis.com"']),
 (MA, "Tool", "Cuckoo Sandbox", "https://github.com/cuckoosandbox/cuckoo", "Open-source automated malware analysis sandbox (unmaintained; CAPE is its successor).", ['"cuckoo sandbox"', '"cuckoosandbox"']),
 (MA, "Tool", "YARA", "https://virustotal.github.io/yara/", "Pattern-matching tool for identifying and classifying malware.", ['"yara" malware', '"yara rules"']),
 (MA, "Tool", "FLARE-VM", "https://github.com/mandiant/flare-vm", "Scripts that turn a Windows VM into a malware analysis workstation.", ['"flare-vm"', '"FLARE VM"']),
 (MA, "Tool", "REMnux", "https://remnux.org", "Linux distribution for malware analysis.", ['"remnux"']),
 (MA, "Tool", "capa", "https://github.com/mandiant/capa", "Identifies capabilities in executable files.", ['"mandiant/capa"', '"fireeye/capa"']),
 (MA, "Tool", "Volatility", "https://volatilityfoundation.org", "Memory forensics framework.", ['"volatilityfoundation"', '"volatility" "memory forensics"']),
 (MA, "Tool", "Sysinternals Suite", "https://learn.microsoft.com/en-us/sysinternals/", "Process Monitor, Process Explorer, Autoruns and other Windows internals utilities.", ['"sysinternals"']),
 (MA, "Tool", "pestudio", "https://www.winitor.com", "Static analysis tool for Windows executables.", ['"pestudio"']),
 (MA, "Tool", "CyberChef", "https://gchq.github.io/CyberChef/", "GCHQ's web app for decoding, decrypting and transforming data.", ['"cyberchef"']),
 (MA, "Reading", "MalAPI.io", "https://malapi.io", "Maps Windows APIs to the malware techniques that use them.", ['"malapi.io"']),
 # ---------------- Reverse Engineering
 (RE, "Tool", "Ghidra", "https://ghidra-sre.org", "NSA's open-source reverse engineering suite with a decompiler.", ['"ghidra"']),
 (RE, "Tool", "radare2", "https://rada.re/n/", "Open-source command-line reverse engineering framework.", ['"radare2"']),
 (RE, "Tool", "Cutter / Rizin", "https://cutter.re", "Open-source RE platform (Cutter GUI on the Rizin framework).", ['"cutter.re"', '"rizin"']),
 (RE, "Tool", "IDA Pro / IDA Free", "https://hex-rays.com/ida-free", "Hex-Rays' disassembler and decompiler.", ['"IDA Pro"']),
 (RE, "Tool", "Binary Ninja", "https://binary.ninja", "Reverse engineering platform with a scriptable intermediate language.", ['"Binary Ninja"', '"binaryninja"']),
 (RE, "Tool", "x64dbg", "https://x64dbg.com", "Open-source x64/x32 debugger for Windows.", ['"x64dbg"']),
 (RE, "Tool", "Frida", "https://frida.re", "Dynamic instrumentation toolkit.", ['"frida.re"']),
 (RE, "Tool", "angr", "https://angr.io", "Python binary analysis framework with symbolic execution.", ['"angr.io"', '"angr" "symbolic execution"']),
 (RE, "Tool", "pwntools", "https://github.com/Gallopsled/pwntools", "CTF framework and exploit development library.", ['"pwntools"']),
 (RE, "Tool", "pwndbg", "https://github.com/pwndbg/pwndbg", "GDB/LLDB plug-in for exploit development and reversing.", ['"pwndbg"']),
 (RE, "Tool", "GEF", "https://github.com/hugsy/gef", "GDB Enhanced Features for exploit developers and reverse engineers.", ['"hugsy/gef"', '"GDB Enhanced Features"']),
 (RE, "Tool", "ImHex", "https://imhex.werwolv.net", "Hex editor for reverse engineers, with a pattern language.", ['"imhex"']),
 (RE, "Tool", "jadx", "https://github.com/skylot/jadx", "Dex to Java decompiler for Android apps.", ['"jadx"']),
 (RE, "Tool", "dnSpy", "https://github.com/dnSpyEx/dnSpy", ".NET debugger and assembly editor.", ['"dnSpy"']),
 (RE, "Book", "Reverse Engineering for Beginners", "https://beginners.re", "Dennis Yurichev's free book (also titled Understanding Assembly Language).", ['"beginners.re"', '"Reverse Engineering for Beginners"']),
 (RE, "Book", "Hacking: The Art of Exploitation", "https://nostarch.com/hacking2.htm", "Jon Erickson's introduction to C, assembly, memory corruption and shellcode.", ['"Art of Exploitation" Erickson', '"Hacking: The Art of Exploitation"']),
 (RE, "Book", "Practical Binary Analysis", "https://practicalbinaryanalysis.com", "Dennis Andriesse's book on building Linux binary analysis tools.", ['"Practical Binary Analysis"']),
 (RE, "Lab", "Microcorruption", "https://microcorruption.com", "Embedded security CTF: exploit a lock's MSP430 firmware in a browser debugger.", ['"microcorruption"']),
 (RE, "Lab", "pwn.college", "https://pwn.college", "Arizona State University's free platform teaching binary exploitation and systems security.", ['"pwn.college"']),
 (RE, "Lab", "crackmes.one", "https://crackmes.one", "Community-uploaded crackmes for practising reversing.", ['"crackmes.one"']),
 (RE, "Lab", "pwnable.kr", "https://pwnable.kr", "Wargame with pwn challenges of increasing difficulty.", ['"pwnable.kr"']),
 (RE, "Lab", "Exploit Education", "https://exploit.education", "Protostar, Phoenix, Fusion and Nebula VMs for learning exploitation (formerly exploit-exercises).", ['"exploit.education"', '"exploit-exercises"']),
 (RE, "Lab", "ROP Emporium", "https://ropemporium.com", "Challenges that teach return-oriented programming.", ['"ropemporium"', '"ROP Emporium"']),
 (RE, "Lab", "Flare-On Challenge", "https://flare-on.com", "Annual reverse engineering contest from the FLARE team.", ['"flare-on.com"', '"flare-on" fireeye', '"flare-on" mandiant']),
 (RE, "Course", "RPISEC Modern Binary Exploitation", "https://github.com/RPISEC/MBE", "Course materials and labs from RPI's binary exploitation class.", ['"RPISEC/MBE"', '"Modern Binary Exploitation"']),
 (RE, "Course", "OpenSecurityTraining", "https://p.ost2.fyi", "Free classes on x86 assembly, OS internals, reversing and exploitation.", ['"opensecuritytraining"', '"ost2.fyi"']),
 (RE, "Course", "Nightmare", "https://guyinatuxedo.github.io", "Intro to binary exploitation and reversing built around CTF challenges.", ['"guyinatuxedo"']),
 (RE, "Course", "Azeria Labs ARM tutorials", "https://azeria-labs.com", "Tutorials on ARM assembly and ARM exploit development.", ['"azeria-labs"', '"azeria labs"']),
 (RE, "Repo", "how2heap", "https://github.com/shellphish/how2heap", "Shellphish's repository of heap exploitation techniques.", ['"how2heap"']),
 (RE, "Reading", "Smashing the Stack for Fun and Profit", "http://phrack.org/issues/49/14.html", "Aleph One's 1996 Phrack article on stack buffer overflows.", ['"Smashing the Stack for Fun and Profit"']),
 (RE, "Reading", "Phrack", "http://phrack.org", "Long-running hacker e-zine of exploitation research.", ['"phrack.org"', '"phrack.com"']),
 (RE, "Reading", "Google Project Zero blog", "https://googleprojectzero.blogspot.com", "Detailed vulnerability research and exploit write-ups.", ['"googleprojectzero.blogspot.com"']),
 # ---------------- Cloud & DevSecOps
 (CL, "Lab", "flAWS / flAWS2", "http://flaws.cloud", "Scott Piper's challenges teaching common AWS security mistakes.", ['"flaws.cloud"', '"flaws2.cloud"']),
 (CL, "Lab", "CloudGoat", "https://github.com/RhinoSecurityLabs/cloudgoat", "Rhino Security Labs' vulnerable-by-design AWS deployment tool.", ['"cloudgoat"']),
 (CL, "Lab", "Kubernetes Goat", "https://github.com/madhuakula/kubernetes-goat", "Vulnerable-by-design Kubernetes cluster for learning.", ['"kubernetes-goat"', '"Kubernetes Goat"']),
 (CL, "Lab", "EKS Cluster Games", "https://eksclustergames.com", "Wiz's Kubernetes security CTF.", ['"eksclustergames"', '"EKS Cluster Games"']),
 (CL, "Lab", "The Big IAM Challenge", "https://bigiamchallenge.com", "Wiz's AWS IAM misconfiguration CTF.", ['"bigiamchallenge"', '"Big IAM Challenge"']),
 (CL, "Reading", "Hacking the Cloud", "https://hackingthe.cloud", "Encyclopedia of cloud attack techniques.", ['"hackingthe.cloud"']),
 (CL, "Reading", "Summit Route", "https://summitroute.com", "Scott Piper's AWS security blog, including the AWS Security Maturity Roadmap.", ['"summitroute"']),
 (CL, "Reading", "tl;dr sec", "https://tldrsec.com", "Clint Gibler's weekly security newsletter with heavy AppSec and cloud coverage.", ['"tldrsec"']),
 (CL, "Reading", "The SOC2 Starting Seven", "https://www.latacora.com/blog/2020/03/12/the-soc-starting/", "Latacora on the security basics to get right before a SOC2 audit.", ['"SOC2 Starting Seven"', '"latacora.com/blog/2020/03/12"']),
 (CL, "Reading", "BeyondCorp", "https://cloud.google.com/beyondcorp", "Google's papers on its zero-trust access model.", ['"beyondcorp"']),
 (CL, "Reading", "CIS Benchmarks", "https://www.cisecurity.org/cis-benchmarks", "Consensus hardening baselines for operating systems, cloud providers and Kubernetes.", ['"CIS benchmarks"', '"CIS benchmark"']),
 (CL, "Reading", "SLSA", "https://slsa.dev", "Supply-chain Levels for Software Artifacts framework.", ['"slsa.dev"']),
 (CL, "Book", "Building Secure and Reliable Systems", "https://sre.google/books/", "Google's free book on designing, implementing and maintaining secure systems.", ['"Building Secure and Reliable Systems"']),
 (CL, "Repo", "my-arsenal-of-aws-security-tools", "https://github.com/toniblyx/my-arsenal-of-aws-security-tools", "Curated list of open-source AWS security tools.", ['"my-arsenal-of-aws-security-tools"']),
 (CL, "Tool", "Pacu", "https://github.com/RhinoSecurityLabs/pacu", "AWS exploitation framework.", ['"RhinoSecurityLabs/pacu"', '"pacu" aws']),
 (CL, "Tool", "ScoutSuite", "https://github.com/nccgroup/ScoutSuite", "Multi-cloud security auditing tool.", ['"ScoutSuite"', '"Scout Suite"', '"Scout2"']),
 (CL, "Tool", "Prowler", "https://github.com/prowler-cloud/prowler", "Open-source cloud security assessment tool.", ['"prowler" aws', '"prowler-cloud"', '"toniblyx/prowler"']),
 (CL, "Tool", "Stratus Red Team", "https://stratus-red-team.cloud", "Emulates cloud attack techniques for testing detection.", ['"stratus-red-team"', '"Stratus Red Team"']),
 (CL, "Tool", "Trivy", "https://github.com/aquasecurity/trivy", "Scanner for vulnerabilities and misconfigurations in containers, code and IaC.", ['"trivy"']),
 (CL, "Tool", "Checkov", "https://github.com/bridgecrewio/checkov", "Static analysis for infrastructure-as-code.", ['"checkov"']),
 (CL, "Tool", "tfsec", "https://github.com/aquasecurity/tfsec", "Static analysis for Terraform (now folded into Trivy).", ['"tfsec"']),
 (CL, "Tool", "Semgrep", "https://semgrep.dev", "Pattern-based static analysis for many languages.", ['"semgrep"']),
 (CL, "Tool", "Gitleaks", "https://github.com/gitleaks/gitleaks", "Finds secrets in git repositories.", ['"gitleaks"']),
 (CL, "Tool", "TruffleHog", "https://github.com/trufflesecurity/trufflehog", "Finds and verifies leaked credentials.", ['"trufflehog"']),
 (CL, "Tool", "kube-bench", "https://github.com/aquasecurity/kube-bench", "Checks Kubernetes against the CIS benchmark.", ['"kube-bench"']),
 (CL, "Tool", "Falco", "https://falco.org", "Runtime threat detection for containers and Kubernetes.", ['"falco.org"', '"falcosecurity"', '"falco" sysdig']),
 (CL, "Tool", "Open Policy Agent", "https://www.openpolicyagent.org", "General-purpose policy engine for policy-as-code.", ['"openpolicyagent"', '"Open Policy Agent"']),
 (CL, "Tool", "Sigstore", "https://www.sigstore.dev", "Signing and verification for software artifacts.", ['"sigstore"']),
 (CL, "Tool", "SOPS", "https://github.com/getsops/sops", "Editor for encrypted secrets files.", ['"mozilla/sops"', '"getsops"']),
 (CL, "Tool", "HashiCorp Vault", "https://developer.hashicorp.com/vault", "Secrets management and encryption service.", ['"hashicorp vault"', '"vaultproject.io"']),
 # ---------------- Foundations & CTFs (cross-domain)
 (F, "Lab", "OverTheWire", "https://overthewire.org/wargames/", "Wargames starting with Bandit, which teaches the Linux command line.", ['"overthewire"']),
 (F, "Lab", "picoCTF", "https://picoctf.org", "Carnegie Mellon's beginner-friendly CTF with a year-round practice gym.", ['"picoctf"']),
 (F, "Lab", "Hack The Box", "https://www.hackthebox.com", "Vulnerable machines and challenges for practising penetration testing.", ['"hackthebox"', '"Hack The Box"']),
 (F, "Lab", "TryHackMe", "https://tryhackme.com", "Guided, browser-based security rooms and learning paths.", ['"tryhackme"']),
 (F, "Lab", "VulnHub", "https://www.vulnhub.com", "Downloadable vulnerable VMs.", ['"vulnhub"']),
 (F, "Lab", "Root Me", "https://www.root-me.org", "Hundreds of challenges across web, crypto, cracking and more.", ['"root-me.org"']),
 (F, "Lab", "Hack This Site", "https://www.hackthissite.org", "Long-running free hacking challenge site.", ['"hackthissite"']),
 (F, "Lab", "SANS Holiday Hack Challenge", "https://www.sans.org/mlp/holiday-hack-challenge", "SANS's free annual CTF.", ['"Holiday Hack Challenge"', '"holidayhackchallenge"']),
 (F, "Reading", "CTFtime", "https://ctftime.org", "Calendar of CTF events, team rankings and write-ups.", ['"ctftime"']),
 (F, "Reading", "CTF Field Guide", "https://trailofbits.github.io/ctf/", "Trail of Bits' guide to getting started with CTFs.", ['"CTF Field Guide"', '"trailofbits.github.io/ctf"']),
 (F, "Reading", "MITRE ATT&CK", "https://attack.mitre.org", "Knowledge base of adversary tactics and techniques.", ['"attack.mitre.org"', '"MITRE ATT&CK"']),
 (F, "Video", "LiveOverflow", "https://www.youtube.com/@LiveOverflow", "YouTube channel on binary exploitation, web hacking and CTFs.", ['"liveoverflow"']),
 (F, "Video", "IppSec", "https://ippsec.rocks", "Hack The Box walkthrough videos, searchable by technique.", ['"ippsec"']),
 (F, "Course", "MIT 6.858 Computer Systems Security", "https://css.csail.mit.edu/6.858/", "MIT's systems security class (now 6.5660), with lecture videos on OCW and public labs.", ['"6.858" MIT', '"css.csail.mit.edu/6.858"']),
 (F, "Course", "Stanford CS 155: Computer and Network Security", "https://cs155.stanford.edu", "Stanford's security course; slides and projects online.", ['"cs155" stanford', '"cs155.stanford.edu"']),
 (F, "Course", "UC Berkeley CS 161: Computer Security", "https://textbook.cs161.org", "Berkeley's security course with a free online textbook.", ['"cs161.org"', '"cs161" berkeley']),
 (F, "Book", "Security Engineering (Ross Anderson)", "https://www.cl.cam.ac.uk/archive/rja14/book.html", "Ross Anderson's textbook on building dependable distributed systems; much of it free online.", ['"Security Engineering" Anderson']),
 (F, "Tool", "Metasploit", "https://www.metasploit.com", "Penetration testing framework.", ['"metasploit"']),
 (F, "Tool", "Kali Linux", "https://www.kali.org", "Debian-based distribution for penetration testing.", ['"kali linux"']),
 (F, "Tool", "Nmap", "https://nmap.org", "Network scanner.", ['"nmap"']),
 (F, "Tool", "Wireshark", "https://www.wireshark.org", "Network protocol analyser.", ['"wireshark"']),
]


# Highest-scoring story matched the name but is about something else (reviewed by hand).
NO_TOP = {"SecLists", "UC Berkeley CS 161: Computer Security", "Stanford CS 155: Computer and Network Security", "Root Me", "Hacking the Cloud", "OALabs", "NetExec (formerly CrackMapExec)", "Gitleaks", "Burp Suite", "Wireshark", "jadx", "VirusTotal", "Metasploit", "CIS Benchmarks",
          "IDA Pro / IDA Free", "radare2", "pwndbg", "mitmproxy", "hashcat", "MITRE ATT&CK", "vx-underground",
          "Security Engineering (Ross Anderson)", "CTFtime", "VulnHub", "PowerSploit / PowerView"}

def get(path, **params):
    base = path if path.startswith("https://") else f"https://hn.algolia.com/api/v1/{path}"
    url = base + "?" + urllib.parse.urlencode(params)
    if url not in CACHE:
        for attempt in range(5):
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    raw = r.read()
                    if r.headers.get("Content-Encoding") == "gzip": raw = gzip.decompress(raw)
                    CACHE[url] = json.loads(raw)
                break
            except Exception as e:                      # rate limit / flaky network: back off
                if attempt == 4: raise
                time.sleep(5 * (attempt + 1))
        time.sleep(0.15)
    return CACHE[url]


BASE = dict(typoTolerance="false", advancedSyntax="true", queryType="prefixNone", attributesToHighlight="")

def search(q, tag):
    extra = {"restrictSearchableAttributes": "title,url"} if tag == "story" else {}
    return get("search", query=q, tags=tag, hitsPerPage=1000,
               attributesToRetrieve="created_at_i,points,title", **BASE, **extra)

def year_count(q, tag, y):
    a = int(time.mktime((y, 1, 1, 0, 0, 0, 0, 0, 0))) - time.timezone
    b = int(time.mktime((y + 1, 1, 1, 0, 0, 0, 0, 0, 0))) - time.timezone
    extra = {"restrictSearchableAttributes": "title,url"} if tag == "story" else {}
    return get("search", query=q, tags=tag, hitsPerPage=0,
               numericFilters=f"created_at_i>={a},created_at_i<{b}", **BASE, **extra)["nbHits"]

def tag_stats(queries, tag):
    """-> ({year: count}, all_hits).  Exact (deduplicated) unless a query exceeds Algolia's
    1000-hit window; then count only the biggest single query per year (a lower bound)."""
    res = [(q, search(q, tag)) for q in queries]
    hits = {h["objectID"]: h for _, r in res for h in r["hits"]}
    if any(r["nbHits"] > len(r["hits"]) for _, r in res):
        q = max(res, key=lambda x: x[1]["nbHits"])[0]
        years = {y: year_count(q, tag, y) for y in YEARS}
    else:
        years = collections.Counter(time.gmtime(h["created_at_i"]).tm_year for h in hits.values())
    return {y: n for y, n in years.items() if n}, list(hits.values())


# Second source: Stack Exchange Q&A (free API, 300 requests/day without a key; results are cached).
SE_FILTER = "!SyjNqbwGU2NWZ210M0"        # default fields + .total
SE_SITES = {C: ["security", "crypto"], RE: ["security", "reverseengineering"]}

def se_stats(cat, q):
    """-> (posts mentioning q, {year: count} from the newest 100 posts per site)."""
    total, years = 0, collections.Counter()
    for site in SE_SITES.get(cat, ["security"]):
        d = get("https://api.stackexchange.com/2.3/search/excerpts", q=q, site=site,
                pagesize=100, sort="creation", filter=SE_FILTER)
        if "error_message" in d: raise SystemExit(f"Stack Exchange API: {d['error_message']}")
        time.sleep(d.get("backoff", 0))
        total += d["total"]
        years.update(time.gmtime(i["creation_date"]).tm_year for i in d["items"])
    return total, dict(years)


def mine(c):
    cat, typ, name, url, desc, queries = c
    cy, _ = tag_stats(queries, "comment")
    sy, stories = tag_stats(queries, "story")
    years = {y: cy.get(y, 0) + sy.get(y, 0) for y in sorted(set(cy) | set(sy))}
    top = max(stories, key=lambda h: h.get("points") or 0, default=None)
    if name in NO_TOP: top = None
    se, se_years = se_stats(cat, queries[0])
    return dict(cat=cat, type=typ, name=name, url=url, desc=desc, q=queries[0],
                comments=sum(cy.values()), stories=sum(sy.values()), se=se,
                mentions=sum(years.values()) + se, years=years,
                allYears=sorted(set(years) | set(se_years)),
                top=top and dict(id=top["objectID"], title=top.get("title") or "", points=top.get("points") or 0))


def check_links(items):
    bad = []
    for it in items:
        req = urllib.request.Request(it["url"], headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) link-check"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                status = r.status
        except Exception as e:
            status = getattr(e, "code", None) or repr(e)
        if status != 200:
            bad.append((status, it["name"], it["url"]))
    return bad


if __name__ == "__main__":
    names = [c[2] for c in CANDIDATES]
    assert len(names) == len(set(names)), "duplicate candidate names"
    assert all(c[1] in {"Lab", "Course", "Book", "Reading", "Video", "Repo", "Tool"} for c in CANDIDATES)
    out = []
    try:
        for i, c in enumerate(CANDIDATES):
            out.append(mine(c))
            print(f"{i+1}/{len(CANDIDATES)} {c[2]}: {out[-1]['mentions']} mentions ({out[-1]['se']} SE), {len(out[-1]['allYears'])} yrs", flush=True)
    finally:
        CACHE_F.write_text(json.dumps(CACHE))
    keep = [r for r in out if r["mentions"] >= MIN_MENTIONS and len(r["allYears"]) >= MIN_YEARS]
    print("\nDROPPED (below threshold):")
    for r in out:
        if r not in keep: print(f"  {r['cat']}: {r['name']} ({r['mentions']} mentions, {len(r['allYears'])} yrs)")
    if "--check-links" in sys.argv:
        print("\nLINKS NOT RETURNING 200:")
        for b in check_links(keep): print("  ", b)
    keep.sort(key=lambda r: -r["mentions"])
    data = dict(generated=time.strftime("%Y-%m-%d"), minMentions=MIN_MENTIONS, minYears=MIN_YEARS,
                candidates=len(out), items=keep)
    (HERE / "data.js").write_text("window.DATA = " + json.dumps(data, indent=1) + ";\n")
    print(f"\nwrote data.js: {len(keep)} of {len(out)} candidates kept")
