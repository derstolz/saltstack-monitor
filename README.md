# saltstack-monitor
This project is based on the saltstack automation framework. See https://www.saltstack.com/ for more info.

Saltstack WebMonitor is used for the two purposes:
<br/>1. Communicate with a WebMonitorMinion and ask him to collect information about web server's logs.
<br/>2. Receive this information, analyze it and print a report about suspicious traffic received by the web server.
<br/>3. According to the printed report, push generated iptables drop statements to the minion.

You can (and probably should) review the generated statements before pushing them, you also can receive a geolocation lookup about collected threats. You can run the WebMonitor in daemon mode to keep watching your WebMonitorMinion(s).

<br/> use ./web_monitor.py --help to get more info how to run it.
