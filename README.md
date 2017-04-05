This repository contains the Counter-RAPTOR Tor client code with a new entry guard relay selection algorithm, as proposed in the *Counter-RAPTOR: Safeguarding Tor Against Active Routing Attacks* paper (http://www.ieee-security.org/TC/SP2017/program.html). This is not the original Tor code. This code is built upon Tor version 0.2.7.6. **This should be considered experimental software.**

To build:
	sh autogensh && ./configure && make
	(Optional: make install)

Configuration file:
	/usr/local/etc/tor/torrc
	(Or /etc/tor/torrc)
	
Sample configuration:
	Resilience 0.5
	UseEntryGuardsAsDirGuards 0

Explanation:
1. Resilience value (e.g. 0.5) needs to be in [0,1]. 
2. Default UseEntryGuardsAsDirGuards is set to 1. However, we have not changed the DirGuard selection to use our entry guard selection algorithm in this version yet. Thus, we need to set this option to 0 so that DirGuard and EntryGuard selections can be performed separately. We expect to update this in the next version, so setting this option would not be necessary. 

For other resources on Tor, please refer to:
	https://www.torproject.org/
	https://www.torproject.org/docs/documentation.html
	https://wiki.torproject.org/projects/tor/wiki/doc/TorifyHOWTO
	https://www.torproject.org/docs/faq.html

