# saltstack-monitor
A bounde of scripts based on the SaltStack automation software which can help to monitor your minion(s) activity.

This project is based on the saltstack automation framework. See https://www.saltstack.com/ for more info.

Saltstack WebMonitor is used for the two purposes:
<br/>1. Communicate with a WebMonitorMinion and ask him to collect information about web server's logs.
<br/>2. Receive this information, analyze it and print a report about suspicious traffic received by the web server.
<br/>2.a. According to the printed report, push generated iptables drop statements to the minion.
