#!/usr/bin/env python3
import argparse
import configparser
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from enum import Enum

import requests


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config',
                        help='Use the specified config file with properties.')
    parser.add_argument('-s', '--saltstack', action='store_true',
                        help='Use Saltstack as a transport for your commands to the watched minions.')
    parser.add_argument('-m', '--minions', dest='minions',
                        help='Provide a file with new-line separated list of the minion id(s) and their log path '
                             'e.g - prod212:/var/log/nginx/access.log '
                             'which you want to monitor and push the rules to')
    parser.add_argument('-sc', '--suspicious-chunks', dest='suspicious_chunks',
                        help='Provide a new-line separated list of the chunks that should be checked '
                             'in the incoming logs from the minion. If a log line contains any of the entry from this '
                             'list, then it will be marked as suspicious request.')
    parser.add_argument('-st', '--sleep-timer', dest='sleep_timer',
                        help='Optional. Provide a sleep timer for the web monitor, in seconds. Default is 60s.')
    parser.add_argument('-l', '--last', dest='last',
                        help='Optional. Provide a time delta in the following format: "10d 8h" '
                             'to receive data from the remote machine. Default is 20d')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Optional. Run Web Monitor as a daemon. In daemon mode, '
                             'Web Monitor can periodically interact with your minions, '
                             'receive data from them and then print their current status. '
                             'Without this options, Web Monitor will do its lifecycle for one time and exit.')
    parser.add_argument('-b', '--ban-timer', dest='ban_timer',
                        help='Optional. Provide a time period on which the threats should be banned. '
                             'Default is 1 hour. '
                             'It should be a string in the following format: "1hr", "10min", "5d"')
    parser.add_argument('-p', '--push', action='store_true',
                        help='Optional. Push generated block statements to the minion(s). '
                             'They should be applied as soon as they arrived. Default is false.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Optional. Print the explain information about the most dangerous impacts. '
                             'Default is false')
    parser.add_argument('-g', '--geolookup', action='store_true',
                        help='Optional. Defines that Web Monitor should perform a geo-location lookup '
                             'for the current impacts')

    options = parser.parse_args()
    if not options.saltstack and not options.config:
        parser.error('Use should provide something to do; '
                     'at least a config file or --saltstack. Use --help for more info')
    if not options.minions and not options.config:
        parser.error('Minion(s) file should be provided, use --help for more info')
    if not options.config and (not options.suspicious_chunks or len(options.suspicious_chunks) < 1):
        parser.error('You have to provide a new-line separated list to check and compare the incoming logs with. '
                     'Use --help for more info')
    return options


class AccessLogParser:
    def __init__(self, suspicious_chunks, logs, duration_time):
        if not suspicious_chunks or len(suspicious_chunks) < 1:
            raise Exception("There are no masks or patterns to look for. "
                            "You have to provide a list with string values to compare requests with them.")
        if not logs or type(logs) != list:
            raise Exception("Incorrect value passed for the logs. It should be a list of lines from access.log")
        if not duration_time:
            duration_time = '1d'
        self.log_pattern_rgx = r'(?P<source>.*) - - ' \
                               r'\[(?P<date>.*) .*\] ' \
                               r'\"(?P<request>.*)\" ' \
                               r'(?P<response>\d{3} \d*) ' \
                               r'\"(?P<referer>.*)\" ' \
                               r'\"(?P<useragent>.*)\"'
        self.suspicious_chunks = suspicious_chunks
        self.last_time = self.parse_last_time(duration_time)
        self.logs = logs

    @staticmethod
    def parse_last_time(last):
        try:
            timedelta_string = last
            td = {}
            _days = re.search(r'\d*(?=d)', timedelta_string)
            if _days: td['days'] = int(_days.group(0))
            _hours = re.search(r'\d*(?=h)', timedelta_string)
            if _hours: td['hours'] = int(_hours.group(0))
            _minutes = re.search(r'\d*(?=m)', timedelta_string)
            if _minutes: td['minutes'] = int(_minutes.group(0))
        except Exception as e:
            print('ERROR PARSING LOGS: ' + str(e))

        parsing_start_time = datetime.now() - timedelta(days=td.pop('days', 0),
                                                        hours=td.pop('hours', 0),
                                                        minutes=td.pop('minutes', 0))
        return parsing_start_time

    def parse_logs(self):
        parsed_logs = []
        for line in self.logs:
            try:
                log_entry = re.search(self.log_pattern_rgx, line)
                log_timestamp = datetime.strptime(log_entry['date'], "%d/%b/%Y:%H:%M:%S")

                # print(str(log_timestamp) + ' --> ' + str(self.last_time) + ' --> ' + str(log_timestamp > self.last_time))
                if log_timestamp > self.last_time:
                    log = {'source': log_entry['source'],
                           'date': log_entry['date'],
                           'request': log_entry['request'],
                           'response': log_entry['response'],
                           'referer': log_entry['referer'],
                           'useragent': log_entry['useragent'],
                           'is_suspicious': any([chunk in log_entry['request'] for chunk in self.suspicious_chunks])}
                    parsed_logs.append(log)
            except Exception as e:
                print('ERROR PARSING LOG LINE: ' + str(e))

        return parsed_logs


"""
    Impact is an entity represents an activity record. 
    It contains a source, number of hits and all requests made my this person.
"""


class Impact:
    """
        @:param source - source IP address of the possible intruder.
        @:param hits - a number of requests made by the possible intruder
        @:param is_dangerous - a flag defines that this intruder can be dangerous and he has a lot of hits
        @:param is_pushed -
               a flag indicates that this impact was reported back to the minion and he should be already blocked.
    """

    def __init__(self, source, hits, is_dangerous=False, is_pushed=False):
        self.source_address = source
        self.events = []
        self.hits = hits
        self.suspicious_hits = 0
        self.is_dangerous = is_dangerous
        self.is_pushed = is_pushed

    """
        Extract all HTTP requests from the incoming events as a list of strings.
    """

    def extract_requests(self):
        return [eve.request for eve in self.events]

    """
        Print explaining information about this impact (source address, requests and hits).
    """

    def explain(self):
        def print_requests(impact):
            for req in impact.extract_requests():
                print(f'\n\t{req}; ', end='')
            print()

        req = self.extract_requests()
        if req and len(req) > 0:
            print(f'\n\n{self.source_address} --> ')
            print_requests(self)

    """
        Convert events into the impacts. Link given events to the created impacts.
    """

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
            suspicious_hits = len([eve for eve in events if eve.source == source and eve.is_suspicious])
            impact = Impact(source, hits)
            impact.suspicious_hits = suspicious_hits
            impacts.append(impact)
        for i in impacts:
            for eve in events:
                if eve.source == i.source_address:
                    i.events.append(eve)
        return impacts

    """
        Check if this impact was already analyzed before.
    """

    @staticmethod
    def is_already_known(impacts_list, impact):
        return any(impact.source_address == i.source_address for i in impacts_list)

    @staticmethod
    def is_already_banned(banned_impacts_list, impact):
        return any(impact.source_address == i.source_address for i in banned_impacts_list)


"""
    Host threat level.
    CRITICAL means that your server had a heavy load in his last time.
    RED and YELLOW indicates that server has a lot of suspicious traffic but still not enough to mark is as CRITICAL.
    GREEN means that host is reachable and responding with a low number of events.
    UNKNOWN means that your host is unreachable or your minion can not report back because of any reason.
"""


class ThreatLevel(Enum):
    CRITICAL = 4
    RED = 3
    YELLOW = 2
    GREEN = 1
    UNKNOWN = 0


"""
    Event represent a converted message which was marked as a suspicious one.
    Each event can be false-positive, so you have to check them properly.
"""


class Event:
    def __init__(self, source, date, request, response, referer, user_agent, is_suspicious, received_event=None):
        self.source = source
        self.date = date
        self.request = request
        self.response = response
        self.referer = referer
        self.user_agent = user_agent
        self.is_suspicious = is_suspicious
        self.received_event = received_event


"""
   WebMonitor is responsible for the minions web-servers logs monitoring. 
   It will periodically interact with his minions to check their logs and perform threat analyses.
   Web-minion will send a list of json strings which is representing the 'Event' entity described above
   then analyze them and generate ban statements. Those statements could be pushed to the minion via saltstack.
"""


class WebMonitor:
    """
        @:param minion_id - a saltstack minion id to communicate with.
        @:param config_file - a configuration file which is used instead of the cli options.
        web-monitor.conf is a configuration example.

        @:param default_sleep_timer - how long monitor should wait before he should recheck the minions status
        @:param download_data_since - last period of time to pull information about. eg: 10d / 100d / 60m
        @:param push_banned_list - a boolean indicates that WebMonitor should push created ban statements to the minion.
        Default is false.
        Without this options, WebMonitor will simply analyze events and warn you about the most aggressive attempts.

        @:param be_verbose - increase verbosity, print detailed information about the most aggressive impacts
        @:param geolookup - collect geo location info about current threats.
    """

    def __init__(self, minion=None, config_file=None, default_sleep_timer=None, download_data_since=None,
                 ban_timer=None, push_banned_list=False, be_verbose=False,
                 geolookup=False, suspicious_chunks=None):
        if not minion and not config_file:
            raise Exception("Nothing to do, please provide a minion id or a config file with minions")
        if ":/" not in minion:
            raise Exception("Please, provide a correct minion pattern in format - prod212:/path/to/log/file")
        if not suspicious_chunks or len(suspicious_chunks) < 1:
            raise Exception(
                'You have to provide a new-line separated list to check and compare the incoming logs with.')

        self.events = []
        if config_file:
            config = configparser.ConfigParser()
            config.read(config_file)
            minion_name = config['Hosts']['Minions'].split(':')[0]
            self.minion_id = minion_name
            self.remote_logs_file = config['Hosts']['Minions'].split(':')[1]
            self.sleep_timer = int(config['Monitor']['PollingIntervalInSeconds'])
            self.download_data_since = config['Monitor']['DownloadDataForLast']
            self.impact_stats_file = config['Monitor']['BannedFile']
            self.should_push_banned_list = config['Monitor']['ShouldPushBannedList']
            self.verbose = config['Monitor']['Verbosity']
            self.suspicious_chunks = config['Monitor']['SuspiciousChunksFile']
            self.ban_timer_as_str = config['Monitor']['BanTimer']
        else:
            minion_name = minion.split(':')[0]
            remote_log_path = minion.split(':')[1]
            self.minion_id = minion_name
            if not default_sleep_timer:
                self.sleep_timer = 60
            else:
                self.sleep_timer = int(default_sleep_timer)
            if not download_data_since:
                self.download_data_since = '1d'
            else:
                self.download_data_since = download_data_since
            self.impact_stats_file = self.minion_id + '_' + 'stats.json'
            if ban_timer:
                self.ban_timer_as_str = ban_timer
            else:
                self.ban_timer_as_str = '1d'
            self.verbose = be_verbose
            self.remote_logs_file = remote_log_path
            self.geolookup = geolookup
            self.suspicious_chunks = suspicious_chunks

        self.ban_timer = self.parse_ban_time(self.ban_timer_as_str)
        self.is_alive = False
        self.threat_level = ThreatLevel.UNKNOWN
        self.number_of_suspicious_events = 0
        self.impacts = []
        self.dangerous_impacts = []
        self.pushed_impacts = []
        self.ban_history = self.minion_id + '_' + 'ban_history.json'
        self.should_push_banned_list = push_banned_list

    DATE_TIME_PATTERN = '%H:%M:%S %d/%m/%Y'

    @staticmethod
    def get_current_date_time():
        return datetime.now().strftime(WebMonitor.DATE_TIME_PATTERN)

    @staticmethod
    def get_next_unban_date_time(ban_timer):
        return (datetime.now() + ban_timer).strftime(WebMonitor.DATE_TIME_PATTERN)

    @staticmethod
    def parse_ban_time(time_str):
        regex = re.compile(r'((?P<days>\d+?)d)?((?P<hours>\d+?)hr)?((?P<minutes>\d+?)min)?')
        parts = regex.match(time_str)
        if not parts:
            return
        parts = parts.groupdict()
        time_params = {}
        for name, param in parts.items():
            if param:
                time_params[name] = int(param)
        return timedelta(**time_params)

    @staticmethod
    def get_ban_expiration_time(ban_timer):
        if 'hr' in ban_timer:
            return ban_timer.replace('hr', ' hours')
        if 'min' in ban_timer:
            return ban_timer.replace('min', ' minutes')
        if 'd' in ban_timer:
            return ban_timer.replace('d', ' days')

    """
        Execute a command on the remote minion.
        Command will be executed on the minion with id stored in the self.minion_id

        @:param bash_syntax - define that provided command is a pure bash command e.g.: pwd && ls -l 
                              that should be forwarded to the minion 'as is'
        @:param salt_syntax - define that provided command is a salt statement e.g.: salt prod1 cmd.run 'uname -a'
                              and should be forwarded to the minion.
    """

    def exec_on_minion(self, command, bash_syntax=False, salt_syntax=False):
        if not bash_syntax and not salt_syntax:
            raise Exception("No syntax scheme provided, you should choose bash_syntax or salt_syntax")

        try:
            exec_result = None
            if salt_syntax:
                exec_result = subprocess.check_output(command)
            if bash_syntax:
                exec_result = subprocess.check_output(['salt', self.minion_id, 'cmd.run', command, 'shell=/bin/bash'])
            if exec_result:
                try:
                    result = exec_result.decode('utf-8').split('\n')
                    formatted_result = [x.strip() for x in result]
                    return formatted_result
                except:
                    self.log('Error while parsing response from the minion')
        except Exception as e:
            return

    """
        Save a log message with a minion id and current time prefix
        @:param msg - message to log
    """

    def log(self, msg):
        print(f'[{self.minion_id}]:[{datetime.now().strftime(self.DATE_TIME_PATTERN)}] - {msg}')

    """
        Run web-monitor in daemon mode. 
        This daemon will periodically interact with his minions with a provided sleep interval.
    """

    def daemon(self):
        while True:
            self.work()
            self.log(f'Sleeping for the {str(timedelta(seconds=self.sleep_timer))} sec(s)')
            time.sleep(int(self.sleep_timer))

    """
        Run the full lifecycle. Each step of this cycle is described bellow.
    """

    def work(self):
        self.ping()
        self.status()
        self.identify_threat_level()

        if self.threat_level != ThreatLevel.UNKNOWN:
            self.analyze_threats()
            if self.should_push_banned_list:
                self.push()
            self.save_impact_stats()
        self.report()

    """
        Test that minion is reachable 
    """

    def ping(self):
        error_message = 'The salt master could not be contacted.'
        self.log('Receiving ' + str(self.minion_id) + ' status...')
        try:
            minion_heartbeat = self.exec_on_minion(['salt', self.minion_id, 'test.ping'], salt_syntax=True)
            if minion_heartbeat and error_message not in str(minion_heartbeat):
                self.is_alive = True
        except KeyboardInterrupt:
            print('\n\nInterrupted')
            exit(1)
        except:
            self.is_alive = False
            return

    """
        Receive input from the minion, parse it into the events and identify current threat status.
    """

    def status(self):
        if self.is_alive:
            def get_last_events():
                if not self.remote_logs_file.startswith('/var/log') or not self.remote_logs_file.endswith('access.log'):
                    self.log(
                        f'REMOTE LOG PATH CONTAINS INCORRECT VALUES: {self.remote_logs_file}\n'
                        f'Please provide the file path starting with /var/log and ending with access.log')
                    return
                self.events.clear()

                command = f'cat {self.remote_logs_file}'
                minion_response = self.exec_on_minion(command, bash_syntax=True)
                if minion_response:
                    return list(minion_response)

            try:
                r = get_last_events()
            except Exception as e:
                self.log(str(e))
                return
            if r and len(r) > 3:
                events = r[3:-1]
                log_parser = AccessLogParser(self.suspicious_chunks, events, self.download_data_since)
                parsed_logs = log_parser.parse_logs()
                self.parse_events(parsed_logs)

    """
        Convert incoming events from the minion into the Event object and store them in web-monitor memory.
    """

    def parse_events(self, events):
        def str_to_event_object(e):
            dict = e
            if len(dict.keys()) > 0:
                self.threat_level = ThreatLevel.GREEN
            if dict:
                event = Event(
                    dict['source'],
                    dict['date'],
                    dict['request'],
                    dict['response'],
                    dict['referer'],
                    dict['useragent'],
                    dict['is_suspicious'],
                    e)
                return event

        for e in events:
            eve = str_to_event_object(e)
            if eve:
                self.events.append(eve)

    """
        Identify current minion status. 
        Monitor will increase the threat level if he will receive a lot of events from the minion
        CRITICAL level for less then 1h would means that your server is under the siege
    """

    def identify_threat_level(self):
        self.number_of_suspicious_events = len([eve for eve in self.events if eve.is_suspicious])
        if self.number_of_suspicious_events > 0:

            if self.number_of_suspicious_events < 100:
                self.threat_level = ThreatLevel.GREEN
            elif 100 < self.number_of_suspicious_events < 500:
                self.threat_level = ThreatLevel.YELLOW
            elif 500 < self.number_of_suspicious_events < 1000:
                self.threat_level = ThreatLevel.RED
            elif self.number_of_suspicious_events > 1000:
                self.threat_level = ThreatLevel.CRITICAL

    """
        Analyze received input. Define the impacts. Define dangerous impacts.
    """

    def analyze_threats(self):
        if self.number_of_suspicious_events == 0:
            return
        self.impacts.clear()
        self.dangerous_impacts.clear()

        self.impacts = Impact.calculate_impact_statistic(events=self.events)
        for i in self.impacts:
            if i.suspicious_hits > 100:
                self.dangerous_impacts.append(i)
        if self.geolookup:
            self.collect_geolookup()

    """
        Read stats file about all saved dangerous impacts.
    """

    def read_stats_file(self):
        existing_stats = []
        try:
            with open(self.impact_stats_file, 'r', encoding='utf-8') as read_fd:
                for i in read_fd.readlines():
                    if i and i != '':
                        impact = json.loads(i)
                        existing_stats.append(impact)
            return existing_stats
        except FileNotFoundError:
            # do nothing
            pass

    """
        Parse created impacts and store them into file.
    """

    def save_impact_stats(self):
        if len(self.dangerous_impacts) > 0:
            for impact in self.dangerous_impacts:
                self.log_impact_stats(self.impact_stats_file, impact)

    """
        Print a report about minion(s) status, his(their) statistic and addresses pushed to be banned.
    """

    def report(self):
        if self.is_alive:
            is_alive_message = 'Host is up'
        else:
            is_alive_message = 'Host is down'

        report_message = \
            f'\n\tStatus: {is_alive_message}' \
                f'\n\tThreat level: {self.threat_level.name}' \
                f'\n\tTotal requests received for last {self.download_data_since}: ' \
                f'{len(self.events)}'
        if self.threat_level != ThreatLevel.UNKNOWN and self.number_of_suspicious_events > 0:
            report_message += \
                f'\n\tSuspicious requests received for last {self.download_data_since}: ' \
                    f'{self.number_of_suspicious_events}' \
                    f'\n\n\tNon-aggressive IP addresses: {len(self.impacts) - len(self.dangerous_impacts)}' \
                    f'\n\tAggressive IP addresses: {len(self.dangerous_impacts)} ' \
                    f'({sum(di.hits for di in self.dangerous_impacts)} hits)' \
                    f'\n\tTotal IP addresses: {len(self.impacts)}'
        if len(self.pushed_impacts) > 0:
            report_message += '\n\tPushed IP addresses to block: ' + str(len(self.pushed_impacts))

        self.log(report_message)
        if self.verbose:
            for impact in self.dangerous_impacts:
                impact.explain()

    """
    Collect geo-location results about threats location
    """

    def collect_geolookup(self):
        def geo_lookup(ip):
            url = f'http://api.geoiplookup.net/?query={ip}'

            response = requests.get(url)

            try:
                if response.status_code == 200:
                    root = ET.fromstring(response.text)
                    geo_result = {}
                    for child in root[0][0]:
                        geo_result[child.tag.title()] = child.text
                        # ISSUE with receiving '&' character literally (and probably others) in lookup response. Encoding?
                    return geo_result
                else:
                    return None
            except Exception as e:
                print(f'Something went wrong during {ip} lookup: {e}')

        if self.impacts and len(self.impacts) > 0:
            for imp in self.impacts:
                imp.geo_location = {}
                print('Collecting geo-lookup about ' + str(imp.source_address) + " --> ", end="")
                geo = geo_lookup(imp.source_address)
                if geo:
                    print('OK')
                    for k, v in geo.items():
                        if k and v:
                            print(k + ' --> ' + v)
                    imp.geo_location = geo
                else:
                    print('FAILED')

    """
        Save a log about banned IP address.
    """

    def log_ban_event(self, file_name, impact):
        with open(file_name, 'a', encoding='utf-8') as write_fd_banned_explained:
            explanation = \
                {'timestamp': self.get_current_date_time(),
                 'banned_until': self.get_next_unban_date_time(self.ban_timer),
                 'source_address': impact.source_address,
                 'hits': impact.hits,
                 'suspicious_hits': impact.suspicious_hits}
            json.dump(explanation, write_fd_banned_explained)
            write_fd_banned_explained.write('\n')

    """
        Save a log about dangerous impact which has a lot of hits.
    """

    def log_impact_stats(self, file_name, impact):
        with open(file_name, 'a', encoding='utf-8') as write_fd:
            stats = \
                {
                    'timestamp': self.get_current_date_time(),
                    'source_address': impact.source_address,
                    'hits': impact.hits,
                    'suspicious_hits': impact.suspicious_hits,
                    'is_blocked': impact.is_pushed
                }
            json.dump(stats, write_fd)
            write_fd.write('\n')

    """
        Push created ban statements to the minion.
        This action (if succeed) will block all traffic between pushed address and the remote minion.
        After statement was pushed, address will be stored in memory and will not be pushed anymore.
    """

    def push(self):
        def execute_ban_on_minion(address):
            if address and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", address):
                expiration_time = self.get_ban_expiration_time(self.ban_timer_as_str)
                command = f"iptables " \
                    f"-I INPUT -s {address} -j DROP && " \
                    f"at now + {expiration_time} <<< 'iptables -D INPUT -s {address} -j DROP'"

                self.log(f'Attempting to block {address}')
                blocking_response = self.exec_on_minion(command, bash_syntax=True)

                if blocking_response:
                    if type(blocking_response) == list and len(blocking_response) > 2 and not any(
                            'error' in m for m in blocking_response):
                        return True

        for impact in self.dangerous_impacts:
            if self.check_if_ban_required(self.ban_history, self.pushed_impacts, impact):
                is_banned = execute_ban_on_minion(address=impact.source_address)
                if is_banned:
                    impact.is_pushed = True
                    self.log_ban_event(self.ban_history, impact)
                    self.log(
                        impact.source_address + f' was blocked '
                        f'for {self.get_ban_expiration_time(self.ban_timer_as_str)}. '
                        f'See {self.ban_history} file for the details.')
                    self.pushed_impacts.append(impact)

    @staticmethod
    def check_if_ban_required(banned_file, pushed_impacts, impact):
        address = impact.source_address
        if any(address == i.source_address for i in pushed_impacts):
            return False
        try:
            with open(banned_file, 'r', encoding='utf-8') as ban_history:
                for line in ban_history:
                    line = line.replace('\n', '')
                    log = json.load(line)
                    print(log)
                    ban_timestamp = datetime.strptime(log['banned_until'], WebMonitor.DATE_TIME_PATTERN)
                    if log['source'] == impact.source_address and ban_timestamp < datetime.now():
                        return True
        except FileNotFoundError:
            pass
        return True


def __main__():
    options = get_arguments()
    if options.config:
        # FIXME: TO BE IMPLEMENTED
        web_monitor = WebMonitor(config_file=options.config)
        web_monitor.daemon()
    elif options.saltstack:
        minions = []
        suspicious_chunks = []
        with open(options.suspicious_chunks, 'r', encoding='utf-8') as sc_file:
            for line in sc_file:
                suspicious_chunks.append(line.replace('\n', ''))
        with open(options.minions, 'r', encoding='utf-8') as minions_file:
            for line in minions_file:
                if line.startswith("#"):
                    continue
                minions.append(line.replace('\n', ''))
        if len(minions) == 0:
            raise Exception(
                "Minion(s) list is empty. Please, specify a new-line separated file with minion(s) and their log path, "
                "e.g. - ubuntu:/var/log/nginx/access.log.\nThe '#' character will comment out your minion.")
        if len(minions) > 1:
            if options.daemon:
                monitors = []
                for m in minions:
                    web_monitor = WebMonitor(m,
                                             default_sleep_timer=options.sleep_timer,
                                             download_data_since=options.last,
                                             push_banned_list=options.push,
                                             be_verbose=options.verbose,
                                             geolookup=options.geolookup,
                                             suspicious_chunks=suspicious_chunks,
                                             ban_timer=options.ban_timer)
                    monitors.append(web_monitor)
                while True:
                    for web_monitor in monitors:
                        web_monitor.work()
                    sleep_timer = options.sleep_timer
                    if not sleep_timer:
                        sleep_timer = 60
                    print(
                        f'[master]:[{datetime.now()}] - Sleeping for the ' + str(
                            timedelta(seconds=sleep_timer)) + ' sec(s)')
                    time.sleep(sleep_timer)

            else:
                for m in minions:
                    web_monitor = WebMonitor(m,
                                             default_sleep_timer=options.sleep_timer,
                                             download_data_since=options.last,
                                             push_banned_list=options.push,
                                             be_verbose=options.verbose,
                                             geolookup=options.geolookup,
                                             suspicious_chunks=suspicious_chunks,
                                             ban_timer=options.ban_timer)
                    web_monitor.work()
        else:
            web_monitor = WebMonitor(minions[0],
                                     default_sleep_timer=options.sleep_timer,
                                     download_data_since=options.last,
                                     push_banned_list=options.push,
                                     be_verbose=options.verbose,
                                     geolookup=options.geolookup,
                                     suspicious_chunks=suspicious_chunks,
                                     ban_timer=options.ban_timer)
            if options.daemon:
                web_monitor.daemon()
            else:
                web_monitor.work()


try:
    __main__()
except KeyboardInterrupt:
    print('\n\nInterrupted')
    exit(1)
