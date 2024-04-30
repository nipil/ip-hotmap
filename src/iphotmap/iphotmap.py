#!/usr/bin/env python3

import argparse
import dataclasses
import json
import logging
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Optional, Self

ENV_NAME_PATH = 'PATH'

DEFAULT_SLEEP_MAIN_LOOP = 0.1
DEFAULT_TTL_SEC = 3 * 60
DEFAULT_INTERVAL_SEC = 5
DEFAULT_LOG_LEVEL = 'WARNING'


def _signal_handler(sig, frame):
    if sig == signal.SIGINT:
        logging.info("Shutdown requested via SIGINT !")
        App.termination_requested.set()


def get_time_int() -> int:
    return int(time.time())


class AppException(Exception):
    pass


@dataclasses.dataclass
class SharedData:
    tcpdump_active_ips: Optional[tuple[tuple[int, ...], ...]] = None
    lock: threading.Lock = threading.Lock()


def find_cmd_from_env_path(name: str) -> pathlib.Path:
    for p in os.environ[ENV_NAME_PATH].split(':'):
        path = pathlib.Path(p, name)
        try:
            path.stat()
        except FileNotFoundError:
            continue
        return path
    raise FileNotFoundError(f'{name} not found in ${ENV_NAME_PATH}')


class TcpdumpThread(threading.Thread):
    COMMAND = 'tcpdump'

    _RE_ADDRESSES = re.compile(r'^(?:\S+\s+\S+\s+)?'
                               r'(?:'
                               r'IP\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?\s+>\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?:\s+'
                               # r'|'
                               # r'IP6\s+(\S+?)(?:\.\d+)?\s+>\s+(\S+?)(?:\.\d+)?:\s+'
                               r'|'
                               r'ARP,\s+(?:'
                               r'Request\s+who-has\s+(\S+)\s+(?:\S+\s+)?tell\s+(\S+)'
                               r'|'
                               r'Reply\s+(\S+)\s+is-at\s+\S+'
                               r'),'
                               r')')

    @classmethod
    def addresses_from_line(cls, line: str) -> Optional[tuple[str, ...]]:
        match = cls._RE_ADDRESSES.match(line)
        if match:
            return tuple(m for m in match.groups() if m is not None)
        return None

    @classmethod
    def get_available_interfaces(cls):
        try:
            tcpdump_path = str(find_cmd_from_env_path(cls.COMMAND))
        except FileNotFoundError as e:
            raise AppException(e)
        cmd = [tcpdump_path, '--list-interfaces']
        try:
            result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as e:
            raise AppException(e)
        return result.stdout

    def __init__(self, sudo, interface, capture_filter, debug_unknown, interval, hits_ttl, shared_data: SharedData,
                 termination_flag):
        super(TcpdumpThread, self).__init__(daemon=True)
        # checks
        if interface is None:
            raise AppException('No interface specified for tcpdump. '
                               'Please specify one by number or by name, using `--tcpdump-interface` :\n'
                               f'{self.get_available_interfaces()}')
        # params
        self._sudo = sudo
        self._interface = interface
        self._capture_filter = capture_filter
        self._debug_unknown = debug_unknown
        self._interval = interval
        self._hits_ttl = hits_ttl
        self._shared_data = shared_data
        self._termination_flag = termination_flag
        # data
        self._ip_last_seen: dict[str, int] = dict()
        # internal
        self._process_handle: Optional[subprocess.Popen[str]] = None
        self._detected_offset: Optional[int] = None
        self._already_found_parsing_error = False

    def _log_parsing_error_once(self, message):
        if self._already_found_parsing_error:
            return
        self._already_found_parsing_error = True
        logging.warning(message)

    def _request_termination(self):
        logging.info('Requesting termination.')
        self._termination_flag.set()

    def _get_active_ip(self, seen_ip: dict[str, int], current_time: int) -> tuple[tuple[int, ...], ...]:
        threshold_time = current_time - self._hits_ttl
        return tuple(
            tuple(int(x) for x in ip.split('.')) for ip, timestamp in seen_ip.items() if timestamp > threshold_time)

    def _publish_active_ips(self, active_ips):
        # replace data reference for other threads
        with self._shared_data.lock:
            self._shared_data.tcpdump_active_ips = active_ips

    def _process_packets(self, stream):
        seen_address = dict()
        last_time = get_time_int()
        # TODO: do not block on line read if no packet captured, so summary and notification still happen "on time"
        for line in stream:
            # extract
            addresses = self.addresses_from_line(line)
            if addresses is None:
                if self._log_unknown:
                    logging.debug(f'Unrecognized packet line: {line.strip()}')
                continue
            # update
            current_time = get_time_int()
            for address in addresses:
                seen_address[address] = current_time
            # shutdown handler
            if self._termination_flag.is_set():
                break
            # periodic
            elapsed_time = current_time - last_time
            if elapsed_time > self._interval:
                last_time = current_time
                # extract
                active_ips = self._get_active_ip(seen_address, current_time)
                # publish
                self._publish_active_ips(active_ips)

    def _build_command(self):
        tcpdump_path = str(find_cmd_from_env_path(self.COMMAND))
        cmd = [tcpdump_path, '-q', '-l', '-n', '-t', '-i', self._interface]
        if self._sudo:
            cmd.insert(0, 'sudo')
        if self._capture_filter is not None:
            cmd.append(self._capture_filter)
        return cmd

    def _spawn_process(self):
        cmd = self._build_command()
        logging.warning(f'Executing privileged command: {cmd}')
        logging.warning('If it fails, restart the program with `--tcpdump-sudo` option')
        with subprocess.Popen(cmd, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=None) as self._process_handle:
            self._process_packets(self._process_handle.stdout)
            # cleanup
            logging.info('Terminating tcpdump process...')
            self._process_handle.terminate()
            result = self._process_handle.wait()
            logging.info(f'Finished tcpdump with code {result}.')
            if result != 0:
                logging.warning(f'tcpdump exited with non zero return code {result}, requesting termination')
                self._request_termination()

    def run(self):
        logging.info('Starting tcpdump thread...')
        try:
            self._spawn_process()
        except OSError as e:
            logging.error(f'Requesting exit because an error happened during tcpdump processing: {e}')
            self._request_termination()
        logging.info('tcpdump thread finished.')


class HaproxySource:
    def info(self):
        raise NotImplementedError

    def stat(self):
        raise NotImplementedError

    def sessions(self):
        raise NotImplementedError


class Haproxy:
    info: Optional[dict[str, str]]
    stat: Optional[tuple[dict[str, str], ...]]
    sessions: Optional[dict[str, dict[str, str]]]

    SESSION_SPECIAL_CASE = re.compile(r'^(\w+)\[')

    def __init__(self, source: HaproxySource, request_termination: threading.Event):
        self.source = source
        self._request_termination = request_termination
        self.info = None
        self.stat = None
        self.sessions = None

    @staticmethod
    def _extract_dict_name_value(dictionary) -> dict[str, str]:
        return {d['field']['name']: d['value']['value'] for d in dictionary}

    @classmethod
    def _sub_dict_session_items(cls, items):
        for item in items.split():
            key, value = cls.SESSION_SPECIAL_CASE.sub(r'\1=[', item, count=1).split('=', maxsplit=1)
            yield key, value

    @classmethod
    def _dict_sessions(cls, sessions):
        for session in sessions:
            key, items = session.split(': ', maxsplit=1)
            value = dict(cls._sub_dict_session_items(items))
            yield key, value

    def refresh(self) -> Self:
        self.info = self._extract_dict_name_value(self.source.info())
        self.stat = tuple(self._extract_dict_name_value(item) for item in self.source.stat())
        self.sessions = dict(self._dict_sessions(self.source.sessions()))
        return self

    class UnixSocketSource(HaproxySource):
        CMD_INFO = 'show info json'
        CMD_STAT = 'show stat json'
        CMD_SESS = 'show sess'

        BUFFER_SIZE = 4096

        def __init__(self, socket_path):
            self._path = socket_path

        def _get(self, command: str) -> str:
            buf = bytearray()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(self._path)
                    client.sendall(command.encode())
                    while True:
                        chunk = client.recv(self.BUFFER_SIZE)
                        if len(chunk) == 0:
                            logging.warning('received zero bytes')
                            break
                        buf += chunk
            except socket.error as e:
                raise AppException(f'Requesting exit because an error happened during haproxy socket processing: {e}')
            return buf.decode()

        def info(self):
            return json.loads(self._get(self.CMD_INFO))

        def stat(self):
            return json.loads(self._get(self.CMD_STAT))

        def sessions(self):
            return self._get(self.CMD_SESS).splitlines()

    class FileSource(HaproxySource):
        def __init__(self, info_file_json: str, stat_file_json: str, sess_file_raw: str):
            self.info_file_json = info_file_json
            self.stat_file_json = stat_file_json
            self.sess_file_raw = sess_file_raw

        @staticmethod
        def _read_file(file_path: str) -> str:
            try:
                with open(file_path, 'rt') as f:
                    return f.read()
            except OSError as e:
                raise AppException(f'Requesting exit because an error happened during haproxy file processing: {e}')

        def info(self):
            return json.loads(self._read_file(self.info_file_json))

        def stat(self):
            return json.loads(self._read_file(self.stat_file_json))

        def sessions(self):
            return self._read_file(self.sess_file_raw).splitlines()


class App:
    # mutable class attribute, create on
    termination_requested = threading.Event()

    @classmethod
    def main(cls, argv=None):
        if argv is None:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser()
        parser.add_argument('-l', '--log-level', default=DEFAULT_LOG_LEVEL,
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
        parser.add_argument('-i', '--interval', type=int, default=DEFAULT_INTERVAL_SEC)
        parser.add_argument('--hits-ttl', type=int, default=DEFAULT_TTL_SEC)
        parser.add_argument('--tcpdump-interface')
        parser.add_argument('--tcpdump-filter')
        parser.add_argument('--tcpdump-debug-unknown', action='store_true')
        parser.add_argument('--tcpdump-sudo', action='store_true')
        args = parser.parse_args(argv)

        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                            level=getattr(logging, args.log_level.upper()))

        signal.signal(signal.SIGINT, _signal_handler)

        # cross-thread data
        shared_data = SharedData()

        logging.info('Starting tcpdump...')
        try:
            tcpdump = TcpdumpThread(args.tcpdump_sudo, args.tcpdump_interface, args.tcpdump_filter,
                                    args.tcpdump_debug_unknown, args.interval, args.hits_ttl, shared_data=shared_data,
                                    termination_flag=cls.termination_requested)
        except AppException as e:
            logging.error(e)
            return

        # start worker threads
        tcpdump.start()

        # main display loop
        last_time = get_time_int()
        while True:
            # idle
            time.sleep(DEFAULT_SLEEP_MAIN_LOOP)
            current_time = get_time_int()
            elapsed_time = current_time - last_time
            if elapsed_time < args.interval:
                continue
            last_time = current_time
            # pull
            with shared_data.lock:
                tcpdump_active_ips = shared_data.tcpdump_active_ips
            # display
            if tcpdump_active_ips is not None:
                print(f'{len(tcpdump_active_ips)} ip seen in the last {args.hits_ttl} seconds.')
            # exit
            if cls.termination_requested.is_set():
                logging.info('Exiting main display loop...')
                break

        # shutdown
        logging.info('Waiting for worker threads to complete...')
        try:
            tcpdump.join()
            logging.info('Joined thread tcpdump.')
        except KeyboardInterrupt:
            logging.info('Keyboard interrupt while waiting for tcpdump completion.')
            pass
        logging.info('Exiting.')


if __name__ == '__main__':
    App.main()
