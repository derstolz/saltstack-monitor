#!/usr/bin/env python3

from argparse import ArgumentParser
from collections import Counter
import datetime
import json
import logging
from pathlib import Path
import re
import sys

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.WARNING)
logger = logging.getLogger(__name__)
Path('summaries').mkdir(exist_ok=True)

log_pattern_rgx = r'(?P<source>.*) - - ' \
                  r'\[(?P<date>.*) .*\] ' \
                  r'\"(?P<request>.*)\" ' \
                  r'(?P<response>\d{3} \d*) ' \
                  r'\"(?P<referer>.*)\" ' \
                  r'\"(?P<useragent>.*)\"'

suspicious_chunks = ['admin',
                     'php',
                     'phpMyAdmin',
                     'sitemap.xml',
                     'robots.txt',
                     '.php',
                     '.ini',
                     'www.',
                     '?query',
                     '%',
                     '?',
                     '*',
                     '(\'',
                     '(\"',
                     '\')',
                     '\")']


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
        sys.exit('Wrong arguments given. Exiting.')

    parsing_start_time = datetime.datetime.now() - datetime.timedelta(days=td.pop('days', 0),
                                                                      hours=td.pop('hours', 0),
                                                                      minutes=td.pop('minutes', 0))
    return parsing_start_time


def parse_args():
    argparser = ArgumentParser()
    argparser.add_argument('--last', dest='last',
                           help='--last *d *h *m will get the events for the provided period of time')
    argparser.add_argument('-p', '--path', dest='path',
                           help='Path to log file to parse and extract event entries.')
    args = argparser.parse_args()

    if not args.last:
        argparser.error('Last time should be provided. Use --help for more info')
    if not args.path:
        argparser.error('File path should be specified, use --help for info')
    return args


def parse_log_file(path, parsing_start_time):
    with open(path, 'r', encoding='utf-8') as log_file:
        print(f"Parsing {path} ...")
        logs = []
        for line in list(log_file):
            try:
                log_entry = re.search(log_pattern_rgx, line)
                log_timestamp = datetime.datetime.strptime(log_entry['date'], "%d/%b/%Y:%H:%M:%S")

                if log_timestamp > parsing_start_time:
                    log = {'source': log_entry['source'],
                           'date': log_entry['date'],
                           'request': log_entry['request'],
                           'response': log_entry['response'],
                           'referer': log_entry['referer'],
                           'useragent': log_entry['useragent'],
                           'is_suspicious': any([chunk in log_entry['request'] for chunk in suspicious_chunks])}
                    if log['is_suspicious']:
                        logging.info(f"Found suspicious request: {log['request']}")
                    logs.append(log)
            except Exception as e:
                logging.info(f"Exception in line {line}: {e}")

        print(f"Parsed {len(logs)} log entries.")
        now = datetime.datetime.now()
        results_path = \
            f"summaries/{parsing_start_time.strftime('%d-%m-%Y--%H-%M-%S')}-TO-" \
                f"{now.strftime('%d-%m-%Y--%H-%M-%S')}.json"

        with open(results_path, 'w', encoding='utf-8') as json_file:
            json.dump(logs, json_file)

    return logs


def aggregate_logs(logs, column):
    print(f"Counting unique {column}s")
    return Counter([log[column] for log in logs])


args = parse_args()
start_time = parse_last_time(args.last)
path = args.path

logs = parse_log_file(path, start_time)
[print(f"{log}") for log in logs]
