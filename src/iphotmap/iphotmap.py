#!/usr/bin/env python3

import argparse
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
from typing import Optional, Iterator, TypedDict, Sequence, IO

ENV_NAME_PATH = 'PATH'

DEFAULT_SLEEP_LOOP = 0.1
DEFAULT_TTL_SEC = 3 * 60
DEFAULT_INTERVAL_SEC = 5
DEFAULT_LOG_LEVEL = 'WARNING'


class AppException(Exception):
    pass


def _signal_handler(sig: int, frame) -> None:
    if sig == signal.SIGINT:
        logging.info("Shutdown requested via SIGINT !")
        App.termination_requested.set()


def get_time_int() -> int:
    return int(time.time())


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
    ActiveIpsType = list[tuple[int, ...]]

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
        # build tuples because they are not meant to be modified
        match = cls._RE_ADDRESSES.match(line)
        if match:
            return tuple(m for m in match.groups() if m is not None)
        return None

    @classmethod
    def get_available_interfaces(cls) -> str:
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

    def __init__(self, sudo: bool, interface: str, capture_filter: str, debug_unknown: bool, interval: int,
                 hits_ttl: int, termination_flag: threading.Event) -> None:
        super(TcpdumpThread, self).__init__(daemon=True)
        # checks
        if interface is None:
            raise AppException('No interface specified for tcpdump. '
                               'Please specify one by number or by name, '
                               'using `--tcpdump-interface` :\n'
                               f'{self.get_available_interfaces()}')
        # params
        self._sudo = sudo
        self._interface = interface
        self._capture_filter = capture_filter
        self._debug_unknown = debug_unknown
        self._interval = interval
        self._hits_ttl = hits_ttl
        self._termination_flag = termination_flag
        # data
        self._ip_last_seen: dict[str, int] = dict()
        self._active_ips_lock = threading.Lock()
        self._active_ips: 'TcpdumpThread.ActiveIpsType' = []
        # internal
        self._process_handle: Optional[subprocess.Popen[str]] = None
        self._detected_offset: Optional[int] = None

    def request_termination(self) -> None:
        logging.info('Requesting termination in tcpdump thread.')
        self._termination_flag.set()

    def _expire_addresses(self, oldest_time: int):
        # delete in place
        expired = [ip for ip, timestamp in self._ip_last_seen.items() if timestamp < oldest_time]
        for ip in expired:
            self._ip_last_seen.pop(ip)

    def _build_active_ips(self) -> ActiveIpsType:
        # build tuples because they are not meant to be modified
        return [tuple(int(x) for x in ip.split('.')) for ip, _ in self._ip_last_seen.items()]

    def _set_active_ips(self, active_ips: ActiveIpsType) -> None:
        # replace data reference for other threads
        with self._active_ips_lock:
            self._active_ips = active_ips

    def get_active_ips(self) -> ActiveIpsType:
        with self._active_ips_lock:
            return self._active_ips

    def _process_packets(self, stream: IO[str]) -> None:
        last_time = get_time_int()
        # TODO: do not block on line read if no packet captured, so summary and notification still happen "on time"
        for line in stream:
            # shutdown
            if self._termination_flag.is_set():
                break
            # extract
            addresses = self.addresses_from_line(line)
            if addresses is None:
                if self._debug_unknown:
                    logging.debug(f'Unrecognized packet line: {line.strip()}')
                continue
            # update
            current_time = get_time_int()
            for address in addresses:
                self._ip_last_seen[address] = current_time
            # periodic
            elapsed_time = current_time - last_time
            if elapsed_time > self._interval:
                last_time = current_time
                # prune
                oldest_time = current_time - self._hits_ttl
                self._expire_addresses(oldest_time)
                # transform
                active_ips = self._build_active_ips()
                # publish
                self._set_active_ips(active_ips)

    def _build_command(self) -> list[str]:
        tcpdump_path = str(find_cmd_from_env_path(self.COMMAND))
        cmd = [tcpdump_path, '-q', '-l', '-n', '-t', '-i', self._interface]
        if self._sudo:
            cmd.insert(0, 'sudo')
        if self._capture_filter is not None:
            cmd.append(self._capture_filter)
        return cmd

    def _spawn_process(self) -> None:
        cmd = self._build_command()
        logging.warning(f'Executing privileged {cmd} ... if it fails, restart with `--tcpdump-sudo` !')
        with subprocess.Popen(cmd, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=None) as self._process_handle:
            # process
            if self._process_handle.stdout is not None:
                self._process_packets(self._process_handle.stdout)
            else:
                logging.error('Could not capture stdout from tcpdump !')
            # cleanup
            logging.info('Terminating tcpdump process...')
            self._process_handle.terminate()
            result = self._process_handle.wait()
            logging.info(f'Finished tcpdump with code {result}.')
            # log
            if result != 0:
                logging.warning(f'tcpdump exited with non zero return code {result}')
            # terminate
            self.request_termination()

    def run(self) -> None:
        logging.info('Starting tcpdump thread...')
        try:
            self._spawn_process()
        except OSError as e:
            logging.error(f'Requesting exit because an error happened during tcpdump processing: {e}')
            self.request_termination()
        logging.info('tcpdump thread finished.')


class HaproxySource:
    class Field(TypedDict):
        pos: int
        name: str

    class Tags(TypedDict):
        origin: str
        nature: str
        scope: str

    class Value(TypedDict):
        type: str
        value: str

    class FieldTagsValue(TypedDict):
        field: 'HaproxySource.Field'
        tags: 'HaproxySource.Tags'
        value: 'HaproxySource.Value'

    class Info(FieldTagsValue):
        processNum: int

    class Stat(FieldTagsValue):
        objType: str
        proxyId: int
        id: int
        processNum: int

    # https://mypy.readthedocs.io/en/stable/common_issues.html#variance
    InfoType = Sequence[Info]
    StatType = list[Sequence[Stat]]

    def info(self) -> InfoType:
        raise NotImplementedError

    def stat(self) -> StatType:
        raise NotImplementedError

    def sessions(self) -> list[str]:
        raise NotImplementedError


class HaproxySocketSource(HaproxySource):
    CMD_INFO = 'show info json'
    CMD_STAT = 'show stat json'
    CMD_SESS = 'show sess'

    BUFFER_SIZE = 4096

    def __init__(self, socket_path: str) -> None:
        self._path = socket_path

    def _get(self, command: str) -> str:
        buf = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self._path)
                client.sendall(f'{command}\n'.encode())
                while True:
                    chunk = client.recv(self.BUFFER_SIZE)
                    if len(chunk) == 0:
                        break
                    buf += chunk
        except socket.error as e:
            raise AppException(f'Requesting exit because an error happened during haproxy socket processing: {e}')
        return buf.decode()

    def info(self) -> HaproxySource.InfoType:
        return json.loads(self._get(self.CMD_INFO))  # type: ignore[no-any-return]

    def stat(self) -> HaproxySource.StatType:
        return json.loads(self._get(self.CMD_STAT))  # type: ignore[no-any-return]

    def sessions(self) -> list[str]:
        return self._get(self.CMD_SESS).splitlines()


class HaproxyFileSource(HaproxySource):
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

    def info(self) -> HaproxySource.InfoType:
        return json.loads(self._read_file(self.info_file_json))  # type: ignore[no-any-return]

    def stat(self) -> HaproxySource.StatType:
        return json.loads(self._read_file(self.stat_file_json))  # type: ignore[no-any-return]

    def sessions(self) -> list[str]:
        return self._read_file(self.sess_file_raw).splitlines()


class HaproxyThread(threading.Thread):
    InfoType = Optional[dict[str, str]]
    StatType = Optional[list[dict[str, str]]]
    SessionType = Optional[dict[str, dict[str, str]]]

    SESSION_SPECIAL_CASE = re.compile(r'^(\w+)\[')

    def __init__(self, source: HaproxySource, interval: int, termination_flag: threading.Event) -> None:
        super(HaproxyThread, self).__init__(daemon=True)
        # params
        self._source = source
        self._interval = interval
        self._termination_flag = termination_flag
        # data
        self._infos: 'HaproxyThread.InfoType' = None
        self._infos_lock = threading.Lock()
        self._stats: 'HaproxyThread.StatType' = None
        self._stats_lock = threading.Lock()
        self._sessions: 'HaproxyThread.SessionType' = None
        self._sessions_lock = threading.Lock()

    def _set_infos(self, infos: InfoType) -> None:
        with self._infos_lock:
            self._infos = infos

    def get_infos(self) -> InfoType:
        with self._infos_lock:
            return self._infos

    def _set_stats(self, stats: StatType) -> None:
        with self._stats_lock:
            self._stats = stats

    def get_stats(self) -> StatType:
        with self._stats_lock:
            return self._stats

    def _set_sessions(self, sessions: SessionType) -> None:
        with self._sessions_lock:
            self._sessions = sessions

    def get_sessions(self) -> SessionType:
        with self._sessions_lock:
            return self._sessions

    @staticmethod
    def _extract_dict_name_value(items: Sequence[HaproxySource.FieldTagsValue]) -> Iterator[tuple[str, str]]:
        for item in items:
            yield item['field']['name'], item['value']['value']

    @classmethod
    def _sub_dict_session_items(cls, items: str) -> Iterator[tuple[str, str]]:
        for item in items.split():
            key, value = cls.SESSION_SPECIAL_CASE.sub(r'\1=[', item, count=1).split('=', maxsplit=1)
            yield key, value

    @classmethod
    def _dict_sessions(cls, sessions: list[str]) -> Iterator[tuple[str, dict[str, str]]]:
        for session in sessions:
            # haproxy terminates response with an empty line
            if len(session) == 0:
                break
            key, items = session.split(': ', maxsplit=1)
            value = dict(cls._sub_dict_session_items(items))
            yield key, value

    def _refresh(self) -> None:
        source_info = self._source.info()
        gen_name_value = self._extract_dict_name_value(source_info)
        infos = dict(gen_name_value)
        self._set_infos(infos)
        stats = [dict(self._extract_dict_name_value(item)) for item in self._source.stat()]
        self._set_stats(stats)
        sessions = dict(self._dict_sessions(self._source.sessions()))
        self._set_sessions(sessions)

    def request_termination(self) -> None:
        logging.info('Requesting termination in haproxy thread.')
        self._termination_flag.set()

    def _process(self) -> None:
        last_time = get_time_int()
        while not self._termination_flag.is_set():
            # idle
            time.sleep(DEFAULT_SLEEP_LOOP)
            # periodic
            cur_time = get_time_int()
            elapsed = cur_time - last_time
            if elapsed < self._interval:
                continue
            last_time = cur_time
            # work
            logging.debug("Refreshing HAPROXY")
            self._refresh()

    def run(self) -> None:
        logging.info('Starting haproxy thread...')
        try:
            self._process()
        except Exception as e:
            logging.error(f'Requesting exit because an error happened during haproxy processing: {e}')
            self.request_termination()
        logging.info('tcpdump thread finished.')


class App:
    # mutable class attribute, create on
    termination_requested = threading.Event()

    @classmethod
    def main(cls, argv: Optional[list[str]] = None):
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
        parser.add_argument('--haproxy-socket', required=True)
        args = parser.parse_args(argv)

        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                            level=getattr(logging, args.log_level.upper()))

        signal.signal(signal.SIGINT, _signal_handler)

        logging.info('Starting tcpdump analysis...')
        tcpdump = TcpdumpThread(sudo=args.tcpdump_sudo, interface=args.tcpdump_interface,
                                capture_filter=args.tcpdump_filter, debug_unknown=args.tcpdump_debug_unknown,
                                interval=args.interval, hits_ttl=args.hits_ttl,
                                termination_flag=cls.termination_requested)

        logging.info('Starting haproxy analysis...')
        haproxy_source = HaproxySocketSource(args.haproxy_socket)
        haproxy = HaproxyThread(source=haproxy_source, interval=args.interval,
                                termination_flag=cls.termination_requested)

        # start worker threads
        tcpdump.start()
        haproxy.start()

        # main display loop
        last_time = get_time_int()
        while not cls.termination_requested.is_set():
            # idle
            time.sleep(DEFAULT_SLEEP_LOOP)
            # periodic
            cur_time = get_time_int()
            elapsed = cur_time - last_time
            if elapsed < args.interval:
                continue
            last_time = cur_time
            # work
            tcpdump_active_ips = tcpdump.get_active_ips()
            haproxy_infos = haproxy.get_infos()
            haproxy_stats = haproxy.get_stats()
            haproxy_sessions = haproxy.get_sessions()

            # display
            status = []
            if tcpdump_active_ips is not None:
                status.append(f'{len(tcpdump_active_ips)} IP seen by tcpdump in the last {args.hits_ttl} seconds.')
            if haproxy_infos is not None:
                status.append(f'{haproxy_infos["CurrConns"]}/{haproxy_infos["Maxconn"]} connections in HAproxy.')
            if haproxy_stats is not None:
                status.append(f'{len(haproxy_stats)} stat items in HAproxy.')
            if haproxy_sessions is not None:
                status.append(f'{len(haproxy_sessions)} sessions in HAproxy.')
            print(' '.join(status))

        logging.info('Exiting main display loop...')

        # shutdown
        logging.info('Waiting for worker threads to complete...')
        try:
            tcpdump.join()
            logging.info('Joined thread tcpdump.')
        except KeyboardInterrupt:
            logging.info('Keyboard interrupt while waiting for tcpdump completion.')
        logging.info('Exiting.')


if __name__ == '__main__':
    App.main()
