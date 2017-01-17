# Fortress with OSSEC

This script will auto install and configure:

	1. PortSentry:	The Sentry tools provide host-level security services for the Unix platform. PortSentry, Logcheck/LogSentry, and 			HostSentry protect against portscans, automate log file auditing, and detect suspicious login activity on a 				continuous basis.
					
	2. LogCheck: 	Logcheck is a simple utility which is designed to allow a system administrator to view the logfiles which are 				produced upon hosts under their control. It does this by mailing summaries of the logfiles to them, after first 			filtering out "normal" entries. Normal entries are entries which match one of the many included regular 				expression files contain in the database.

	3. ClamAV:	ClamAV® is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.
	
	4. UFW:		Ufw stands for Uncomplicated Firewall, and is program for managing a netfilter firewall. It provides a command 				line interface and aims to be uncomplicated and easy to use.
					
	5. OSSEC:	OSSEC is a scalable, multi-platform, open source Host-based Intrusion Detection System (HIDS). It has a powerful 			 correlation and analysis engine, integrating log analysis, file integrity checking, Windows registry monitoring, 			  centralized policy enforcement, rootkit detection, real-time alerting and active response. It runs on most 				operating systems, including Linux, OpenBSD, FreeBSD, MacOS, Solaris and Windows.
					
	
It will also install and configure the minor required dependencies:

	1. apache2 	
	2. php5 	
	3. nano 
	4. syslog-summary 
	5. libapache2-mod-php5 
	6. python-magic-dbg
	7. python-gdbm-dbg
	8. python-tk-dbg
	9. clamav-daemon
	
The script will also pull two files currently on barnett-labs.com for the install (future pull from github)

	1. clamav-scan.sh 	#Pre-configured virus scan with email report feature. 
	2. clamd.conf  		#Pre-configured .conf file to streamline installation process.
