#!/usr/bin/env python3
from enum import Enum


def get_arguments():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config',
                        help='Use the specified config file with properties.')
    parser.add_argument('-s', '--saltstack', action='store_true',
                        help='Use Saltstack as a transport for your commands to the watched minions.')
    parser.add_argument('-m', '--minion-id', dest='minion_id',
                        help='Provide a minion_id from the saltstack to receive and analyze data from')
    parser.add_argument('-st', '--sleep-timer', dest='sleep_timer',
                        help='Provide a sleep timer for the web monitor, in seconds')
    parser.add_argument('-l', '--last', dest='last',
                        help='Provide a time delta in "10d 8h" format to receive data from the remote machine.')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run Web Monitor as a daemon. In daemon mode, '
                             'Web Monitor can periodically interact with your minions, '
                             'receive their status and then print the current status. '
                             'Without this options, Web Monitor will simply print the current status and exit.')
    parser.add_argument('-b', '--banned', dest='banned',
                        help='A file contains iptables block statements.'
                             'This file should exist and be writable for the script. '
                             'If not provided, then file would be created and all statements will be written to it.')
    parser.add_argument('-p', '--push', action='store_true',
                        help='Push generated block statements to the minion(s). '
                             'They will apply received statements as soon as they arrived.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Be verbose. Print explain information about the most dangerous impacts')
    options = parser.parse_args()
    if not options.saltstack and not options.config:
        parser.error('Use should provide something to do; '
                     'at least a config file or --saltstack. Use --help for more info')
    if not options.minion_id and not options.config:
        parser.error('Minion ID should be provided, use --help for more info')
    return options


class Impact:
    def __init__(self, source, hits, is_dangerous=False, is_pushed=False):
        self.source_address = source
        self.hits = hits
        self.is_dangerous = is_dangerous
        self.is_pushed = is_pushed
        self.requests = []

    def explain(self):
        def print_requests(impact):
            for req in impact.requests:
                print(f'\n\t{req}; ', end='')

        print(f'\n\n{self.source_address} --> {print_requests(self)}')

    @staticmethod
    def calculate_impact_statistic(events):
        addresses = {}
        for eve in events:
            if eve.source in addresses.keys():
                addresses[eve.source] += 1
            else:
                addresses[eve.source] = 1
        impacts = []
        for source, hits in addresses.items():
            is_dangerous = hits > 100
            impact = Impact(source, hits, is_dangerous)
            impacts.append(impact)
        for i in impacts:
            for eve in events:
                if eve.source == i.source_address:
                    i.requests.append(eve.request)
        return impacts


class ThreatLevel(Enum):
    CRITICAL = 0
    RED = 1
    YELLOW = 2
    GREEN = 3
    UNKNOWN = 4


class Event:
    def __init__(self, source, date, request, response, referer, user_agent, received_event=None):
        self.source = source
        self.date = date
        self.request = request
        self.response = response
        self.referer = referer
        self.user_agent = user_agent
        self.received_event = received_event


"""
   Use this class to monitor your remote instance via provided transport mechanism
"""


class WebMonitor:
    """
        Provide a minion_id to communicate via saltstack
    """

    def __init__(self, minion_id=None, config_file=None, default_sleep_timer=None, download_data_since=None,
                 banned_file=None, push_banned_list=False, be_verbose=False):
        self.events = []
        if not minion_id and not config_file:
            raise Exception("Nothing to do, please provide a minion id or a config file with minions")
        if config_file:
            import configparser
            config = configparser.ConfigParser()
            config.read(config_file)
            self.minion_id = config['Hosts']['Minions']
            self.SLEEP_TIMER_IN_SEC = int(config['Monitor']['PollingIntervalInSeconds'])
            self.download_data_since = config['Monitor']['DownloadDataForLast']
            self.banned_file = config['Monitor']['BannedFile']
            self.should_push_banned_list = config['Monitor']['ShouldPushBannedList']
            self.verbose = config['Monitor']['Verbosity']
        else:
            self.minion_id = minion_id
            if not default_sleep_timer:
                self.SLEEP_TIMER_IN_SEC = 60
            else:
                self.SLEEP_TIMER_IN_SEC = int(default_sleep_timer)
            if not download_data_since:
                self.log('Time for downloading data from was not provided, falling back to the default: 20d')
                self.download_data_since = '20d'
            else:
                self.download_data_since = download_data_since
            if banned_file:
                self.banned_file = banned_file
            else:
                self.banned_file = 'banned.txt'
            self.verbose = be_verbose

        self.is_alive = False
        self.threat_level = ThreatLevel.UNKNOWN
        self.impacts = []
        self.dangerous_impacts = []
        self.pushed_impacts = []
        self.banned_explained_file = 'banned_explained.txt'
        self.should_push_banned_list = push_banned_list

    """
        Provide a command to execute on the remote system
    """

    def exec_on_minion(self, command, bash_syntax=False, salt_syntax=False):
        import subprocess

        try:
            exec_result = None
            if salt_syntax:
                exec_result = subprocess.check_output(command)
            if bash_syntax:
                exec_result = subprocess.check_output(['salt', self.minion_id, 'cmd.run', command])
            if exec_result:
                try:
                    result = exec_result.decode('utf-8').split('\n')
                    formatted_result = [x.strip() for x in result]
                    return formatted_result
                except:
                    self.log('Error on parsing response from the minion')
        except Exception as e:
            self.log('Cannot execute command. Error was: ' + str(e))

    def log(self, msg):
        import datetime
        print(f'[{self.minion_id}]:[{datetime.datetime.now()}] - {msg}')

    def daemon(self):
        import time
        while True:
            self.work()
            self.log(f'Sleeping for the {self.SLEEP_TIMER_IN_SEC / 60} min(s)')
            time.sleep(int(self.SLEEP_TIMER_IN_SEC))

    def parse_events(self, events):
        def str_to_event_object(e):
            import ast
            dict = ast.literal_eval(e)
            if dict and dict['is_suspicious']:
                event = Event(
                    dict['source'],
                    dict['date'],
                    dict['request'],
                    dict['response'],
                    dict['referer'],
                    dict['useragent'],
                    e)
                return event

        for e in events:
            eve = str_to_event_object(e)
            if eve:
                self.events.append(eve)

    def identify_thread_level(self):
        if self.events:
            number_of_events = len(self.events)

            if number_of_events < 100:
                self.threat_level = ThreatLevel.GREEN
            elif 100 < number_of_events < 500:
                self.threat_level = ThreatLevel.YELLOW
            elif 500 < number_of_events < 1000:
                self.threat_level = ThreatLevel.RED
            elif number_of_events > 1000:
                self.threat_level = ThreatLevel.CRITICAL

    def work(self):
        self.ping()
        self.status()
        self.analyze_threats()
        self.report()

        if self.should_push_banned_list:
            self.push()

    def ping(self):
        error_message = 'The salt master could not be contacted.'
        self.log('Receiving minion(s) status...')
        minion_heartbeat = self.exec_on_minion(['salt', self.minion_id, 'test.ping'], salt_syntax=True)
        if minion_heartbeat and error_message not in str(minion_heartbeat):
            self.is_alive = True

    def status(self):
        if self.is_alive:
            def get_last_events():
                self.events.clear()
                command = f'cd /root/web_monitor && python3.7 web_monitor_minion.py --last "{self.download_data_since}"'
                return self.exec_on_minion(command, bash_syntax=True)[4:-1]

            r = get_last_events()
            if r and len(r) > 3:
                if self.threat_level == ThreatLevel.UNKNOWN:
                    self.threat_level = ThreatLevel.GREEN
                events = r[3:-1]
                self.parse_events(events)
            self.identify_thread_level()

    def analyze_threats(self):
        if not self.events or len(self.events) == 0:
            print('No events to process, returning')
            return
        self.impacts.clear()
        self.dangerous_impacts.clear()

        self.impacts = Impact.calculate_impact_statistic(events=self.events)
        for i in self.impacts:
            if i.is_dangerous:
                self.dangerous_impacts.append(i)

    def create_ban_statements(self):
        if len(self.dangerous_impacts) > 0:
            write_fd = open(self.banned_file, 'a', encoding='utf-8')
            read_fd = open(self.banned_file, 'r', encoding='utf-8')
            existing_statements = read_fd.readlines()
            saved_count = 0
            unsaved_count = 0
            for impact in self.dangerous_impacts:
                command = f'/sbin/iptables -A INPUT -s {impact.source_address} -j DROP'
                is_exist = any(command == st.replace('\n', '') for st in existing_statements)
                if not is_exist:
                    saved_count += 1
                    write_fd.write(command)
                    write_fd.write('\n')
                    write_fd.flush()
                else:
                    unsaved_count += 1
            write_fd.close()
            read_fd.close()
            if saved_count > 0 and not self.should_push_banned_list:
                self.log(
                    f'{saved_count} new blocking rule(s) has been added. Use --push '
                    f'to send them to the impacted server.')


        else:
            self.log('No dangerous impacts, nothing to ban')

    def report(self):
        if self.is_alive:
            is_alive_message = 'Host is up'
        else:
            is_alive_message = 'Host is down'
        self.log(f'\n\tStatus: {is_alive_message}'
                 f'\n\tThreat level: {self.threat_level}'
                 f'\n\tTotal suspicious events received for last {self.download_data_since}: {len(self.events)}'
                 f'\n\n\tNon-aggressive impacts: {len(self.impacts) - len(self.dangerous_impacts)}'
                 f'\n\tAggressive impacts: {len(self.dangerous_impacts)} '
                 f'({sum(di.hits for di in self.dangerous_impacts)} hits)'
                 f'\n\tTotal impacts: {len(self.impacts)}')
        if self.verbose:
            for impact in self.dangerous_impacts:
                impact.explain()
        self.create_ban_statements()

    def push(self):
        def execute_ban_on_minion(address):
            if address and address != "":
                print('Pushing new rule: ' + address, end='')
                command = f'sudo /sbin/iptables -A INPUT --source {address} -j DROP'
                r = self.exec_on_minion(command, bash_syntax=True)
                if r:
                    if type(r) == list and len(r) > 2 and not any('error' in m for m in r):
                        print(' --> OK')

        for impact in self.dangerous_impacts:
            source = impact.source_address
            if any(source == i.source_address for i in self.pushed_impacts):
                continue
            else:
                execute_ban_on_minion(address=f'{impact.source_address}')
                self.pushed_impacts.append(impact)


options = get_arguments()
if options.config:
    web_monitor = WebMonitor(config_file=options.config,
                             default_sleep_timer=options.sleep_timer,
                             banned_file=options.banned,
                             be_verbose=options.verbose)
    web_monitor.daemon()
elif options.saltstack:
    web_monitor = WebMonitor(options.minion_id,
                             default_sleep_timer=options.sleep_timer,
                             download_data_since=options.last,
                             banned_file=options.banned,
                             push_banned_list=options.push,
                             be_verbose=options.verbose)
    if options.daemon:
        web_monitor.daemon()
    else:
        web_monitor.work()
