# saltstack-monitor
This project is based on the saltstack automation framework. See https://www.saltstack.com/ for more info.

Saltstack WebMonitor is used for the three purposes:
<br/>1. Communicate with a minion and ask him to collect web server's logs.
<br/>2. Receive this information, analyze it and print a report about suspicious traffic received by the web server.
<br/>3. Block the suspicious traffic according to the report, pushing generated iptables drop statements to the minion.
<br/>Please refer to the <a href="https://github.com/derstolz/saltstack-monitor/wiki">project wiki</a> to get more info.
<b><h2>Installation:</h2></b>
 
 
 <br/> On the <b>minion</b> side:
  <br/>1. install saltstack: run saltstack-minion-setup.sh from the project repo
  <br/>2. add a master's IP address to the salt-minion configuration file: /etc/salt/minion
  
<br/><br/> On the <b>master</b> side:
  <br/> 1. install saltstack: run saltstack-master-setup.sh from the project repo
  <br/> 2. minion will try to communicate with master as soon as it comes online. you should accept the minion's key and authorize it.
  <br/> # salt-key --list
  <br/> # salt-key --accept <i>minion_id</i>
  <br/> # salt-key --list #to make sure that you have accepted the minion's key
  
<b><h2>Running:</h2></b>
<br>On the <b>minion</b> side:
<br/>(Optional) make sure that you have a link '<i>web-monitor-minion</i>' to web_monitor_minion.py script in the /usr/bin directory, so master would be able to call your minion. Master will ask for a command e.g.: <i>'web-monitor-minion --path /var/log/nginx/access.log --last 10d</i>. In general, the saltstack-minion-setup.sh should do it for you.
<br/><br/>On the <b>master</b> side:
<br/># <b>python3 web_monitor.py --saltstack --minions <i>id:/remote/path/to/logs/access.log</i> --daemon</b>
<br/> to run the master in daemon monitor mode: interact with your minion (or minions - you can provide a comma (,) separated list of all your minions that your want to monitor). Master will print statistics of events received from the minion and suggest you to block the most aggressive addresses.
<br/><br/>#<b>python3 web_monitor.py --saltstack --minions <i>id:/remote/path/to/logs/access.log</i> --daemon --push</b>
<br/> to run the master in daemon monitor mode and push iptables rules to the minion. e.g. of created rules: 'iptables -A INPUT --source 123.213.123.213 -j DROP'
<br/><i>123.213.123.213 here is an IP addresses that was marked as a dangerous one (more than 100 hits)</i>

<br/><br/>You can specify several minions:
<br/># <b>python3 web_monitor.py --saltstack --minions <i>id:/path/to/log,id2:/path/to/log</i></b>

You can (and probably should) review the generated statements before pushing them, you can also receive a geolocation lookup of collected threats. You can run the web-monitor-master in daemon mode to keep watching your web-monitor-minion(s).
<br/><br/> #<b>python3 web_monitor.py --saltstack --minions <i>id:/remote/path/to/logs/access.log</i> --verbose</b>
<br/> to print explanatory information about incoming events - and tell you why some events were marked as dangerous and were suggested to be blocked.
<br/><br/> #<b>python3 web_monitor.py --saltstack --minions <i>id:/remote/path/to/logs/access.log</i> --geolookup</b>
<br/> to perform a geolocation lookup to get overview of the source of the malicious activity.
<br/><br/> use ./web_monitor.py --help to see more options.

