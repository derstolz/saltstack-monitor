# saltstack-monitor
This project is based on the saltstack automation framework. See https://www.saltstack.com/ for more info.

Saltstack WebMonitor is used for the three purposes:
<br/>1. Communicate with a minion and ask him to collect information about web server's logs.
<br/>2. Receive this information, analyze it and print a report about suspicious traffic received by the web server.
<br/>3. According to the printed report, push generated iptables drop statements to the minion.

<b><h2>Installation:</h2></b>
 
 
 <br/> On the <b>minion</b> side:
  <br/>1. install saltstack: run saltstack-minion-setup.sh from the project repo
  <br/>2. add a master's IP address to the salt-minion configuration file: /etc/salt/minion
  
<br/><br/> On the <b>master</b> side:
  <br/> 1. install saltstack: run saltstack-master-setup.sh from the project repo
  <br/> 2. minion will try to communicate with master since he is online. you should accept his key and authorize him.
  <br/> # salt-key --list
  <br/> # salt-key --accept <i>minion_id</i>
  <br/> # salt-key --list #to make sure that you have accept the minion key
  
<b><h2>Running:</h2></b>
<br>On the <b>minion</b> side:
<br/>(Optional) make sure that you have a link '<i>web-monitor-minion</i>' to web_monitor_minion.py script in the /usr/bin directory, so master would be able to call your minion. Master will ask for a command e.g.: <i>'web-monitor-minion --path /var/log/nginx/access.log --last 10d</i>. In general, the saltstack-minion-setup.sh should do it for you.
<br/><br/>On the <b>master</b> side:
<br/># python3 web_monitor.py --saltstack --minion-id <i>minion_id</i> --daemon
<br/> to run the master in daemon monitor mode: interact with your minion (or minions - you can provide a comma (,) separated list of all your minions that your want to monitor). Master will print statistics about events received from the minion and suggest you to block the most aggressive addresses.
<br/><br/>#python3 web_monitor.py --saltstack --minion-id <i>minion_id</i> --daemon --push
<br/> to run the master in daemon monitor mode and push iptables rules to the minion. e.g. of created rules: 'iptables -A INPUT --source 123.213.123.213 -j DROP'
<br/><i>123.213.123.213 here is an IP addresses that was marked as a dangerous one (more than 100 hits)</i>

You can (and probably should) review the generated statements before pushing them, you also can receive a geolocation lookup about collected threats. You can run the WebMonitor in daemon mode to keep watching your WebMonitorMinion(s).

<br/> use ./web_monitor.py --help to get more info how to run it.
