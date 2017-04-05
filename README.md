This repository contains the Counter-RAPTOR Tor client code with a new entry guard relay selection algorithm, as proposed in the *Counter-RAPTOR: Safeguarding Tor Against Active Routing Attacks* paper (http://www.ieee-security.org/TC/SP2017/program.html). This is not the original Tor code. This code is built upon Tor version 0.2.7.6.

**This should be considered experimental software.**

To build: <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sh autogensh && ./configure && make <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(Optional: make install) 

Configuration file: <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/usr/local/etc/tor/torrc <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(Or /etc/tor/torrc)
	
Sample configuration: <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Resilience 0.5 <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;UseEntryGuardsAsDirGuards 0

Explanation:
1. Resilience value (e.g. 0.5) needs to be in [0,1]. 
2. Default UseEntryGuardsAsDirGuards is set to 1. However, we have not changed the DirGuard selection to use our entry guard selection algorithm in this version yet. Thus, we need to set this option to 0 so that DirGuard and EntryGuard selections can be performed separately. We expect to update this in the next version, so setting this option would not be necessary. 

For other resources on Tor, please refer to: <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://www.torproject.org/ <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://www.torproject.org/docs/documentation.html <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://wiki.torproject.org/projects/tor/wiki/doc/TorifyHOWTO <br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://www.torproject.org/docs/faq.html

