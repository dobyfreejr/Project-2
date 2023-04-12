# Cybersecurity
 ##  Penetration Test Report




## *Contact Information*

| Contact Name | Kyle Barbre|
| ------ | ---------- |
| Contact Title   | Sr. Penetration Tester |
| Contact Phone | 888.888.8888 |
| Contact Email  | k.barbre@ctms.com |


## *Document History Pentesting Team*


| Author Name  | Title | 
| ------ | ----------- | 
| Destiny Nevarez | Sr Pentester |
| Derrik Hoke | Sr. Pentester |
| Tyler Jobson | Sr. Pentester |
| Ryan Bryne  | Sr. Pentester |
| Katie Diaz | Sr. Pentester |






# *Introduction*

In accordance with Rekall policies, our organization conducts external and internal penetration tests of its networks and systems throughout the year. The purpose of this engagement was to assess the networks’ and systems’ security and identify potential security flaws by utilizing industry-accepted testing methodology and best practices.

For the testing, we focused on the following:

Attempting to determine what system-level vulnerabilities could be discovered and exploited with no prior knowledge of the environment or notification to administrators.
Attempting to exploit vulnerabilities found and access confidential information that may be stored on systems.
Documenting and reporting on all findings.

All tests took into consideration the actual business processes implemented by the systems and their potential threats; therefore, the results of this assessment reflect a realistic picture of the actual exposure levels to online hackers. This document contains the results of that assessment.

# *Assessment Objective*

The primary goal of this assessment was to provide an analysis of security flaws present in Rekall’s web applications, networks, and systems. This assessment was conducted to identify exploitable vulnerabilities and provide actionable recommendations on how to remediate the vulnerabilities to provide a greater level of security for the environment.

We used our proven vulnerability testing methodology to assess all relevant web applications, networks, and systems in scope. 

Rekall has outlined the following objectives:

**Table 1: Defined Objectives**

Objective
Find and exfiltrate any sensitive information within the domain.
Escalate privileges.
Compromise several machines.





# *Penetration Testing Methodology*

### **Reconnaissance**
 
We begin assessments by checking for any passive (open source) data that may assist the assessors with their tasks. If internal, the assessment team will perform active recon using tools such as Nmap and Bloodhound.

### *Identification of Vulnerabilities and Services*

We use custom, private, and public tools such as Metasploit, hashcat, and Nmap to gain perspective of the network security from a hacker’s point of view. These methods provide Rekall with an understanding of the risks that threaten its information, and also the strengths and weaknesses of the current controls protecting those systems. The results were achieved by mapping the network architecture, identifying hosts and services, enumerating network and system-level vulnerabilities, attempting to discover unexpected hosts within the environment, and eliminating false positives that might have arisen from scanning. 

### *Vulnerability Exploitation*

Our normal process is to both manually test each identified vulnerability and use automated tools to exploit these issues. Exploitation of a vulnerability is defined as any action we perform that gives us unauthorized access to the system or the sensitive data. 

## *Reporting*

Once exploitation is completed and the assessors have completed their objectives, or have done everything possible within the allotted time, the assessment team writes the report, which is the final deliverable to the customer.


## *Scope*

Prior to any assessment activities, Rekall and the assessment team will identify targeted systems with a defined range or list of network IP addresses. The assessment team will work directly with the Rekall POC to determine which network ranges are in-scope for the scheduled assessment. 

It is Rekall’s responsibility to ensure that IP addresses identified as in-scope are actually controlled by Rekall and are hosted in Rekall-owned facilities (i.e., are not hosted by an external organization). In-scope and excluded IP addresses and ranges are listed below. 



# **Executive Summary of Findings**

## **Grading Methodology**

Each finding was classified according to its severity, reflecting the risk each such vulnerability may pose to the business processes implemented by the application, based on the following criteria:

Critical:	 Immediate threat to key business processes.
High:		 Indirect threat to key business processes/threat to secondary business processes.
Medium:	 Indirect or partial threat to business processes. 
Low:		 No direct threat exists; vulnerability may be leveraged with other vulnerabilities.
Informational:    No threat; however, it is data that may be used in a future attack.

As the following grid shows, each threat is assessed in terms of both its potential impact on the business and the likelihood of exploitation:

![]()


## *Summary of Strengths*

While the assessment team was successful in finding several vulnerabilities, the team also recognized several strengths within Rekall’s environment. These positives highlight the effective countermeasures and defenses that successfully prevented, detected, or denied an attack technique or tactic from occurring. 

- An adequate SSL certificate has been set up on the web server.
- Filtering was enabled on certain entry fields on the website, maybe not preventing all exploits, but discouraging less persistent threats.


## *Summary of Weaknesses*

We successfully found several critical vulnerabilities that should be immediately addressed in order to prevent an adversary from compromising the network. These findings are not specific to a software version but are more general and systemic vulnerabilities.

- Passwords were stored in clear text on the website on “hidden” but not locked down pages.
- Password policies are weak and many passwords are guessable.
- Filtering across the website was weak allowing multiple forms of injection through entry fields..
- Sensitive data was accessible from within publicly accessible locations.
- Pages were not set to be static and manipulation of the URL would expose not just site data but server data as well.
- Administrative pages of the site were not password protected properly.
- Actual user accounts were used in creating the contact info for the domain leading to brute force attacks.
- Software patching on all machines wasn’t up to date and allowed for easy exploitation of the systems on the network and from the WAN.
- Ports that were not necessarily needed were left open and not fully configured to prevent intrusion.
- Default passwords for some server services were left active allowing for simple access to critical information..





# **Executive Summary**

Web Vulnerabilities

Flag 1
This flag was found by entering <script>alert(1)</script> in the name entry box on the welcome page. This page is vulnerable to cross site scripting allowing a user the ability to enter their own scripts or commands into the field and have them run against the server potentially allowing access to additional data or even compromising the integrity of future entries.

![]()

Flag 3
This flag was similar to flag 1 and we found it by entering the same <script>alert(1)</script> into the comment field.  Again leaving entry boxes with no filtering for format or keywords leaves a site susceptible to injections of this kind that can compromise not just the site but other users personal data.

![]()

Flag 5
To find flag 5 it was discovered that there was a filter on the entry box, located on the “Memory Planner” page, but it only looked to find the jpg extension somewhere within the name.  Modifying the payload’s extension to include jpg and an additional extension allowed us to upload a payload to the server and receive flag 5.


Flag 8
To discover flag 8 we went to the login page and found that we could add /html to the end of the url and from there it was discovered that the administrator login was included on the page in clear text.

Using this information we logged into the Administrator login and retrieved the flag.

Flag 9
We checked the robots.txt file, used for websearch details, and found that the flag had been entered into the file.  This information is public so don’t put things you want hidden there.


Flag 10
When discovering flag 8 we found a link to /networking.php.  On this page we found a box that used nslookup to return data about domain names and ip addresses.  Upon entering a site we discovered flag 10.

Flag 6
To discover this flag we used a similar technique to what was done in flag 5.  The difference here is the filtering which, instead of just needing .jpg somewhere in the name, needed to have .jpg at the end of the file name.  We created this payload, uploaded it and received flag 6.


Flag 11
Similar to flag 10 this flag was found using the tools found on the networking.php page but using the MX Record Checker entry box.  Entering a website url into the entry box and once the button is pressed the flag is returned.

Flag 4
After just a little testing, on the entry boxes on the /networking.php page, we found that the entry boxes on this page allowed us to perform basic Linux terminal commands. This gave us a full view of the files and folders on the server, allowing us to conduct an immense amount of reconnaissance on the system. We took this information and were able to find that there was a .backup2 file for the About-Rekall page.

Due to some weaknesses in the design of the webpage, which allowed us to open the php files directly rather than it being a fixed page, we were able to load the backup page from the “About Rekall” page, to discover flag 4.






Flag 7
This flag was discovered by using SQL injection on the login page.  Entering ' OR 1 -- - into the login entry box allows us to use an “OR” statement to query the database using an always false statement, which kicks back flag 7.


Flag 15
To discover this flag we first started with doing some recon using the admin networking tools page in the “DNS Check” entry box which allows command entry.  We found a folder containing an old disclaimer text file.













After finding this file we used the weakness found under the “About Rekall” page to view the data contained in the text file we found using directory transversal to move to the folder that it was contained in and found the flag.


Flag 13
An additional page was found at /souvenirs.php where it was discovered we could pass additional commands to the page in the url bar.  Once this was discovered we found we could add a second command that performed a “whoami” lookup and returned the flag.




Linux Vulnerabilities 

Flag 1
To discover this flag we ran the domain name for the company through an online DNS lookup tool and discovered flag 1 under the “Contact Information” mailing address.


Flag 2
To further our testing we needed an IP address to use as a vector to attempt to enter the network.  Using additional online tools we were able to retrieve the IP address using reverse lookup and found it.



Flag 3
To find even more vectors and to attempt to find weaknesses in order to gain access to the network we continued our searching finding that the site was using an RSA SSL certificate.


Flag 4
Once access to the network was established we found flag 4 by running a simple network scan and found 5 individual hosts on the network.



Flag 5
After finding the initial hosts on the network we decided to do an aggressive scan of the network hosts to see if they contained any ports or software that could be exploited.  We discovered the IP address of a system running a program called Drupal, that we wanted to check to see if the version was one that was easy to attack.


Flag 6
Using an open source tool called Nessus against the previously found system we found that the version of the software was indeed vulnerable to an attack as we found a critical vulnerability.

Flag 7
We continued looking at additional hosts on the network for vulnerabilities and found that the particular version of apache tomcat looked to be out of date.


Using an open source tool called Metasploit we were able to search for the particular version of Apache Tomcat and found an exploit that would allow us to gain access to the system.

Once access was obtained we were able to easily search the system and found flag 7.


Flag 8
We continued looking at ways to exploit the additional systems on the network and found a system that contained a particularly exploitable version of Apache.  With some simple searching in Metasploit we found an exploit, called “Shellshock”, that would give us access to the system.




Upon setting the necessary options we were able to run the exploit and gain access to the system.


While examining some of the most important files on the system we were able to find the flag contained in one of those files.






Flag 9
With access to that system still in place we looked in the file containing user accounts and password hashes and found flag 9.


Flag 10
Having collected a number of key pieces of information from the previous systems we continued our pursuit of access to additional systems on the network.  We discovered yet another system that was using a very vulnerable version of Apache and found an exploit using Metasploit.












Upon setting the options for the exploit and running it we were able to establish a session and upon searching we found a compressed file containing the flag.  We used a command within our session to download the file to our system for further analysis.

With the file on our local system we were able to extract the contents and view the flag.




Flag 11
For one of the last systems to test we found an exploit for an older version of Drupal we found on the system.


Upon setting the options for the exploit and running it we were able to gain access to the system.


Once access was established we were able to run several commands to retrieve system information about the system. (This flag was not working to compete on the challenges page but this is the process we took to get the requested information.)

Flag 12
We discovered during our initial network scan that the final system had an open ssh port and was listening for connections.  With information we retrieve during our initial recon of the domain name we entered the user name, and with some simple password guessing were able to obtain access to the system.  Once access was obtained we utilized a vulnerability in the installed version of sudo to escalate our privileges to root which allowed us to view sensitive areas of the system and retrieve the flag.
 a


























Windows Vulnerabilities

Flag 1
Upon doing additional reconnaissance we discovered a GitHub repository for Rekall and while parsing the data contained there we were able to find a user account with a hash.


After passing this hash through an open source tool called John-the-Ripper we were able to easily retrieve the password.








Flag 2
With access to the network established we did an aggressive network scan which exposed the services running on each system.  We found a Windows 10 system that was running a webserver.


Upon browsing to that system we found, using the username and password discovered in the previous recon, and were able to reach the site data containing the flag.











Flag 3
When we found the internal web server we also noted that the system was running an ftp server.  When testing access to that server we found the default “anonymous” user name and password was still active and had full access to the data contained on the server.


Upon searching the data contained we quickly found a file that contained the flag data we needed, and after moving it to our local system were able to view the data and retrieve the flag.













Flag 4
From our initial scan we additionally found that the system that contained the last two flags was also hosting a mail server.  Upon doing some searching we found that the version of SLMail was exploitable due to a well known vulnerability.


Upon setting the options for the exploit and running it we were able to drop to a shell and found a file containing our flag which we were able to retrieve using simple windows command line tools.


Flag 5
Now that we had gained access to the Windows 10 system we started to do initial recon to find other ways to maintain a foothold in the network.  We started this process by creating a payload that would “call home” to our system and allow us to maintain a connection.



Once the payload was generated we uploaded it to the Windows 10 system

In order to keep the payload up and running we needed to schedule a task to run it regularly.  Upon looking through the currently scheduled tasks we found a task named “flag 5” and found the flag under the comment.


Flag 6
Using a module in Metasploit called kiwi, we were able to query the system and found a list of credentials.


Upon retrieving these credentials we pulled them to the local system and again, using John-the-Ripper, we were able to discover the user accounts password. 

Flag 7
While still working with the Windows 10 system we had previously gained access to, we continued to look at the file and folders on the system and found that there was a flag contained in the Public profile in the Documents folder and using a built-in command we were able to view the data contained within.


Flag 8
While doing recon on the Windows 10 system we found that there was a domain admin account cached in the system and were able to retrieve the password hash from that account.


Again, using john-the-ripper, we were able to take that hash and retrieve the password for this account giving us a way to access additional systems with escalated privileges on the network.


With this new account information we decided it was a good time to try and move laterally within the network to try and gain access to additional systems.  The target we decided to pursue was the network domain controller.  We found a tool that allowed us to point to this new system and then move our currently active session to the new system maintaining our access.

Upon setting up the tool and running it we were given a new session to work with.



And upon activating that session we were able to open a shell on the domain controller and with a simple command were able to find the local user accounts that were set up on the system and found the flag there as well. 

Flag 10
Now that we noticed that there was an Administrator account active we wanted to see if we could access this account's password.  Using the kiwi module we were able to run a domain controller tool that allowed us to retrieve a cached password hash for the account.  With enough time we could crack this hash and have the account's password and the “keys to the kingdom”. 


Flag 9
With some additional recon upon the domain controller we found an additional flag on the root of the filesystem.






Summary Vulnerability Overview


Vulnerability
Severity
Filtering in most of the entry fields on the website is inadequate allowing for exploitation through cross-site-scripting, local file inclusion and SQL injection
Critical
Pages of the website were not configured properly allowing manipulation of the URL to expose sensitive information
Critical
Password policies are weak and many passwords are guessable or easily crackable
Critical
User credentials are stored on the server in clear text on insecure administrator pages
High
User credentials stored on publicly exposed website repo on GitHub
High
Out of date packages across all systems on the network
High
Sensitive data was available from publicly accessible locations on the website
Medium
Ports that were not necessarily needed were left open and/or had misconfigured services behind them
Medium
Actual user account information being used for the domain name contact info leads to brute force attacks
Low
Sensitive data stored in local system Public folders
Low



The following summary tables represent an overview of the assessment findings for this penetration test:

Scan Type
Total
Hosts
8
Ports
6


Exploitation Risk
Total
Critical
3
High
2
Medium
3
Low
2











Vulnerability Findings

Vulnerability 1
Findings
Title
Filtering for most entry fields on the website are inadequate or non-existent
Type (Web app / Linux OS / WIndows OS)
Web App
Risk Rating
Critical
Description
Filtering on most of the entry fields is inadequate.  We found that almost all the entry fields were exploitable through the use of a combination of cross-site-scripting, local file inclusion and SQL injection.  Below is a break down of the vulnerable entries:
On the “Welcome” and “Comments” pages both entry fields can have java script run through them giving the attacker the ability to modify the page and/or run injected scripts from there.
On the “Memory Planner” page, both entry fields contained some filtering, however, the first box only looked to make sure the entry contained the extension .jpg anywhere in the name, while the second box only looked to make sure the that the .jpg extension was at the end of the name allowing for local file inclusion by altering the extensions to by-pass the filters.
On the “Login” page it was found that SQL injection using a conditional statement using “AND” or “OR”, in this case “OR”, to send the database an “always false” statement to run as part of the query would return database data.  This process, if left as is, can be utilized to retrieve sensitive data from the database like passwords.
Affected Hosts
totalrekall.xyz
Remediation
To prevent the abuse of these kinds of exploits it is necessary to audit each entry box on the site and specifically set up filters for the kind of data expected such as:
Only allow alphabetical characters in entry fields for fields that are needing only that kind of entry.
For fields that need punctuation, adding filters that limit what punctuation is allowed.
Adding filters that limit all entries containing any form of the word script (capitals, lowercase and any combination of that), any html style tags, or javascript language from being allowed would help limit the vectors that can be used for exploitation.
For file uploads where pictures are involved use metadata filters to verify that the file is actually an image.  Additionally, allowing only files with one extension that matches a list of expected extension types would build upon the filters that are already in place.
Again with SQL injection adding filtering in the boxes for expected data, alphabetical letters for a name entry, or excluding certain characters that would give the impression of an extended query (OR, AND, quotes, numbers, etc)



Vulnerability 2
Findings
Title
Pages of the website were not configured properly allowing manipulation of the URL to expose sensitive information
Type (Web app / Linux OS / WIndows OS)
Web App
Risk Rating
Critical
Description
Due to the design of the website multiple pages are susceptible to having the url being manipulated to expose other server data and retrieve pages that aren’t meant for public viewing.  The following pages were found to be exploitable and in need of securing:
The disclaimer page is written in such a way that it references pages within the file structure of the server, instead of pointing to the exact page, allowing for opening of files from not just the website folder on the hosted server, but also allows directory transversal to access data on the root of the server as well.  This allows access to /etc, /var and any other folder and file on the system that allows read-only access.
A page called /souvenirs.php allows command injection by adding a semicolon and a command to the end of the url.  The basic page has a ?message= added to the end of the url and many commands added to the end of that can retrieve information about the server such as server name.  This can also be used to run any scripts or malware that has been uploaded to the site through local file inclusion techniques.
Affected Hosts
totalrekall.xyz
Remediation 
To fix both of these occurrences it would be best to alter the web site structure to only include direct links to the pages that are to be displayed.  Additionally removing, and archiving to another location, any unnecessary files from the folders containing the web page content would keep people from accidentally finding old copies of pages that could at least cause confusion and at worst expose content Rekall doesn’t want public.



















Vulnerability 3
Findings
Title
Password policies are weak and many passwords are guessable or easily crackable
Type (Web app / Linux OS / WIndows OS)
Web App, Linux OS, Windows OS
Risk Rating
Critical
Description
Across all systems it was found that the passwords used by both basic users and administrators were weak and dictionary attackable.  Using simple wordlists and even guessing we were able to retrieve nearly every password we wanted.
Affected Hosts
totalrekall.xyz,
172.22.117.10, 20
192.168.13.10, 11, 12, 13, 14
Remediation 
Develop and enforce a strong password complexity that requires passwords to be over 12 characters long, upper+lower case, & include a special character.  Also recommending phrases instead of simple words assists with this as well.
Set up two-factor authentication instead of basic authentication to prevent dictionary attacks from being successful.






























Vulnerability 4
Findings
Title
User credentials are stored on the server in clear text on insecure administrator pages
Type (Web app / Linux OS / WIndows OS)
Web App
Risk Rating
High
Description
It was found that if /html or /admin were added to the end of the /login.php page it would expose additional content on the page without having to input any credentials.  Additionally when these pages were exposed, the administrator user name and password had been included in the html code and was exposed in clear text on this page.  This login information also gave us access to the “Admin Networking Tools” and allowed us to run terminal commands against the server further exposing all the files on the server through command injection.
Affected Hosts
totalrekall.xyz
Remediation 
The practice of securing these pages used for website administration are generally locked down behind a secure password.  Also leaving account information, even with a hashed password, anywhere is a horrible idea and should be removed.  Passwords can always be reset and any time they are recorded there is a chance of it being found by the wrong parties.  Additionally the “Admin Networking Tools”, while being convenient, are really awful to be on the server unless absolutely necessary and otherwise should be removed, especially since these tools are not needed for the functionality  of the website and can be run locally on any administrator system locally.

























Vulnerability 5
Findings
Title
User credentials stored on publicly exposed website repo on GitHub
Type (Web app / Linux OS / WIndows OS)
Web App
Risk Rating
High
Description
While having a backup of your website stored in a location like GitHub allows for development and changes with commits, being sure to audit the data stored there is of most importance to prevent sensitive information from being exposed to the public.  We found a file that was stored in the root of the repo that included a user account and password hash, that was again easily hackable and would give access to Apache running on the web server.
Affected Hosts
totalrekall.xyz
Remediation 
It is recommended to first and foremost make the repo containing business information, even just a website, private.  The chances of data being “forgotten” in the code is fairly high and should be protected.  Additionally being sure to set a policy for auditing and properly confirming, all commits should be implemented.  In the endl someone should audit the data currently there and make sure it is current and clean of any sensitive information.


Vulnerability 7
Findings
Title
Out of date packages across all systems on the network
Type (Web app / Linux OS / WIndows OS)
Linux OS, Windows OS
Risk Rating
High
Description
While the systems affected by out of date packages are behind a firewall and potentially not exposed to the WAN, in the event a nefarious individual gets access to the network, either by being a local user or through malware, updating these packages is very important.  We found a number of items that were susceptible to attack, but would be led to believe additional software needs to be upgraded as well.  Here is a list of the software packages we exploited to get started with as they seem to be the most egregious and we were able to confirm that the exploits were usable to gain access to the systems.
Nearly all systems within the 192.168.13.0 ip range are running a version of Apache, and it’s submodules, are exploitable in some fashion
On the system at 192.168.13.13 we found the version of Drupal is susceptible to exploitation and is documented in CVE-2019-6340.  
The system at 192.168.13.10 is running a version of Apache Tomcat JSP that is susceptible to an exploit that can bypass upload filters and push a payload the the system to allow a bind connection.
On system 192.168.13.12 it was found that an exploit is available for Apache Struts that allows remote code execution.
The system at 192.168.13.11, has a version of Apache that is susceptible to the “Shellshock” exploit that again creates a bind connection.  Documentation about this can be found under CVE-2014-6271.
On system 172.22.117.20 we easily found an exploit for the version of SLMail that was installed on this system that allowed for remote code execution.  This was through the POP3 port and service enabled on the mail server.
Affected Hosts
172.22.117.10, 20
192.168.13.10, 11, 12, 13, 14
Remediation 
To prevent most of these exploits a thorough audit of the software running on each system on the network should be conducted.  Starting with the list provided, as they are the most easily identifiable, verifying all software across all systems is updated to the latest stable release is imperative.
To alleviate any issues that might come up with software incompatibility, it would also be recommended to either split services to more virtual systems or containerize those services.  This will also help with updates as you can test changes on snapshots or clones, and when going live with an update you will only have to bring down part of your system if an update requires a restart.  Having a more modular system ensures you are able to keep uptime at a maximum while doing maintenance.
For the final SLMail exploit ensure that having POP3 enabled on the server is necessary, and make sure the software is up-to-date.  Most email clients and hardware (printers, scanners, time clocks, management software, etc) will work just as well, if not better, with IMAP or MS Exchange protocols, which is more secure and better for general user experience.  POP3 is a very insecure protocol and should be avoided.



























Vulnerability 6
Findings
Title
Sensitive data was available from publicly accessible locations on the website
Type (Web app / Linux OS / WIndows OS)
Web App
Risk Rating
Medium
Description
With very little searching we found that the robot.txt file, used for web crawlers to propagate search info and therefore publicly viewable, contained sensitive information that would not just be viewable if someone browses to the page, but is searchable by sites like google.com.
Affected Hosts
totalrekall.xyz
Remediation 
A regular audit of data like this on the site should be made to make sure the data contained within is actually information that needs to be public.


Vulnerability 8
Findings
Title
Ports that were not necessarily needed were left open and/or had misconfigured services behind them
Type (Web app / Linux OS / WIndows OS)
Linux OS, Windows OS
Risk Rating
Medium
Description
Once upon the network we found a few services that offered us a connection due to the ports being open and/or the services, once setup, left in an insecure state.  Below are a list of ports and services we found:
FTP over port 21 on 172.22.117.20.  The issue found here was not that FTP was set up but that the anonymous account is still active and allowed to view all the contents of the FTP server. 
SSH over port 22 on 192.168.13.14.  Again having SSH available on this machine isn’t so much of a problem but not using a key pair to make the connection leaves it open for bruteforce.
Affected Hosts
172.22.117.10, 20
192.168.13.10, 11, 12, 13, 14
Remediation 
To better secure the network a full audit on all machines should be made to make sure that ports and services that are exposed, should be only open if they need to be, and all services, if necessary, are configured in a secure manner.  This particular solution is best if implemented alongside the patching of all of the software on the systems.
For the two items we found and were able to exploit the below will help prevent and remedy these issues.
For the FTP server it would be recommended to disable the anonymous account to prevent unintentional access.
To fix the SSH access to make it more secure it would be recommended to implement a key pair to prevent access from any machine but only systems and accounts that are deemed necessary.


Vulnerability 9
Findings
Title
Actual user account information being used for the domain name contact info leads to brute force attacks
Type (Web app / Linux OS / WIndows OS)
Linux OS, Windows OS
Risk Rating
Low
Description
The information provided to the registrar for contact information is an actual email address of a user for the company instead of a shared mailbox or alias.  The hosts that would be affected could be any on the ount that is in the contact information, usually an admin of some kind, so this causes a major issue if the account password is found to go along with that account.
Affected Hosts
172.22.117.10, 20
192.168.13.10, 11, 12, 13, 14
Remediation 
Many registrars will help mask email addresses by giving a random address through their system that forwards to a designated address.  First check if they offer this service, and if not, we would recommend using a shared mailbox.  This will create a filter for any mail that is received and prevents a user account address from being abused by spam and other undesirable mail. Additionally these kinds of mailboxes can’t be directly logged into which prevents any attempts to perform a brute force attack.


Vulnerability 10
Findings
Title
Sensitive data stored in local system Public folders
Type (Web app / Linux OS / WIndows OS)
Windows OS
Risk Rating
Low
Description
It was found that user account information was stored in the Public folder on the Windows 10 system.  These folders, as the name indicates, are public and don’t require any permissions to view the data within them.  Even guests can access this data.
Affected Hosts
192.168.13.10, 11, 12, 13, 14
Remediation 
Create a policy that directs users to not store sensitive information in Public folders on their systems.  While recording user account login information in any way is not a good practice under any circumstances, storing it on the server in a folder that has explicit permissions will prevent prying eyes from seeing data that isn’t meant for them.


