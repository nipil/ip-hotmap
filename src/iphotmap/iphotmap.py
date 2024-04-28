#!/usr/bin/env python3

import argparse
import dataclasses
import logging
import os
import pathlib
import re
import signal
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


def get_time_int():
    return int(time.time())


class AppException(Exception):
    pass


@dataclasses.dataclass
class SharedData:
    tcpdump_active_ip: int = 0
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


class TcpdumpRecord:
    TOKEN_IN = 'In'
    TOKEN_OUT = 'Out'
    TOKEN_MULTI = 'M'
    TOKEN_IP = 'IP'
    TOKEN_ARP = 'ARP,'
    TOKEN_IP6 = 'IP6'
    TOKEN_IP_UDP = 'UDP'
    TOKEN_IP_TCP = 'tcp'
    TOKEN_IP_ICMP = 'ICMP'

    TOKEN_SUPPORTED = {TOKEN_IP: (TOKEN_IP_UDP, TOKEN_IP_TCP, TOKEN_IP_ICMP), }

    MIN_TOKEN_DETECTION = 2
    ANY_INTERFACE_MARKERS = (TOKEN_IN, TOKEN_OUT, TOKEN_MULTI)
    ANY_INTERFACE_MARKERS_POSITION = 1
    ANY_INTERFACE_MARKERS_OFFSET = 2
    STD_INTERFACE_MARKERS = (TOKEN_IP, TOKEN_IP6, TOKEN_ARP)
    STD_INTERFACE_MARKERS_POSITION = 0
    STD_INTERFACE_MARKERS_OFFSET = 0

    OFFSET_PROTO = 0
    OFFSET_IP_PROTO_SUB = 4
    OFFSET_IP_ADDRESSES = (1, 3)

    SPLIT_RE = re.compile(r'\s+')
    STARTING_IP4_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+)')

    @classmethod
    def is_protocol_supported(cls, proto: str) -> bool:
        return proto in cls.TOKEN_SUPPORTED

    @classmethod
    def is_sub_protocol_supported(cls, proto: str, sub_proto: str) -> bool:
        if not cls.is_protocol_supported(proto):
            raise ValueError(f'Unknown protocol {proto}, cannot check sub-protocol {sub_proto}')
        return sub_proto in cls.TOKEN_SUPPORTED[proto]

    @classmethod
    def _detect_format_offset(cls, tokens: list[str]) -> Optional[int]:
        if len(tokens) >= 2 and tokens[cls.ANY_INTERFACE_MARKERS_POSITION] in cls.ANY_INTERFACE_MARKERS:
            return cls.ANY_INTERFACE_MARKERS_OFFSET
        if len(tokens) >= 1 and tokens[cls.STD_INTERFACE_MARKERS_POSITION] in cls.STD_INTERFACE_MARKERS:
            return cls.STD_INTERFACE_MARKERS_OFFSET
        return None

    @classmethod
    def detect_format_offset_from_line(cls, line) -> Optional[int]:
        tokens = cls._tokenize_line(line)
        return cls._detect_format_offset(tokens)

    @classmethod
    def _tokenize_line(cls, line: str) -> list[str]:
        return cls.SPLIT_RE.split(line.strip())

    @classmethod
    def _get_protocol(cls, tokens: list[str], starting_offset: int) -> str:
        try:
            return tokens[cls.OFFSET_PROTO + starting_offset]
        except IndexError:
            raise ValueError(f'Not enough tokens to detect protocol: {tokens}')

    @classmethod
    def _get_ip_sub_protocol(cls, tokens: list[str], starting_offset: int) -> str:
        # same indices for TOKEN_IP_UDP, TOKEN_IP_TCP, TOKEN_IP_ICMP
        try:
            return tokens[cls.OFFSET_IP_PROTO_SUB + starting_offset]
        except IndexError:
            raise ValueError(f'Not enough tokens to detect sub-protocol: {tokens}')

    @classmethod
    def _get_ip_addresses(cls, tokens: list[str], starting_offset: int) -> Optional[tuple[str, ...]]:
        # Same indices and extraction process for TOKEN_IP_UDP, TOKEN_IP_TCP, TOKEN_IP_ICMP
        try:
            matches = tuple(cls.STARTING_IP4_RE.match(tokens[i + starting_offset]) for i in cls.OFFSET_IP_ADDRESSES)
        except IndexError:
            raise ValueError(f'Not enough tokens to get ip addresses: {tokens}')
        addresses = tuple(match[0] for match in matches if match is not None)
        if len(matches) != len(addresses):
            raise ValueError(f'Some addresses could not be extracted: {tokens}')
        return addresses

    @classmethod
    def _addresses_from_ip_line(cls, tokens: list[str], starting_offset: int) -> Optional[Self]:
        proto_sub = cls._get_ip_sub_protocol(tokens, starting_offset)
        if not cls.is_sub_protocol_supported(cls.TOKEN_IP, proto_sub):
            return None
        return cls._get_ip_addresses(tokens, starting_offset)

    @classmethod
    def addresses_from_line(cls, line: str, starting_offset: int) -> Optional[tuple[str, ...]]:
        if starting_offset is None or starting_offset < 0:
            raise ValueError(f'Invalid starting offset {starting_offset}')
        tokens = cls._tokenize_line(line)
        proto = cls._get_protocol(tokens, starting_offset)
        if not cls.is_protocol_supported(proto):
            return None
        if proto == cls.TOKEN_IP:
            return cls._addresses_from_ip_line(tokens, starting_offset)
        return None


class TcpdumpThread(threading.Thread):
    COMMAND = 'tcpdump'

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

    def __init__(self, sudo, interface, capture_filter, interval, hits_ttl, shared_data: SharedData, termination_flag):
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

    def _get_active_ip_count(self, seen_ip, current_time):
        active_count = 0
        threshold_time = current_time - self._hits_ttl
        for ip, timestamp in seen_ip.items():
            if timestamp > threshold_time:
                active_count += 1
        return active_count

    def _publish(self, active_count):
        # publish data to other threads
        with self._shared_data.lock:
            self._shared_data.tcpdump_active_ip = active_count

    def _process_packets(self, stream):
        seen_address = dict()
        last_time = get_time_int()
        # TODO: do not block on line read if no packet captured, so summary and notification still happen "on time"
        for line in stream:
            # detect
            if self._detected_offset is None:
                self._detected_offset = TcpdumpRecord.detect_format_offset_from_line(line)
                if self._detected_offset is None:
                    logging.info(f'Skipping packet until format detection succeeds : {line}')
                    continue
                logging.info(f'Successfully detected format offset: {self._detected_offset}')
            # extract
            addresses = TcpdumpRecord.addresses_from_line(line, self._detected_offset)
            if addresses is None:
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
                active_count = self._get_active_ip_count(seen_address, current_time)
                # publish
                self._publish(active_count)

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
        parser.add_argument('--tcpdump-sudo', action='store_true')
        args = parser.parse_args(argv)

        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                            level=getattr(logging, args.log_level.upper()))

        signal.signal(signal.SIGINT, _signal_handler)

        # cross-thread data
        shared_data = SharedData()

        logging.info('Starting tcpdump...')
        try:
            tcpdump = TcpdumpThread(args.tcpdump_sudo, args.tcpdump_interface, args.tcpdump_filter, args.interval,
                                    args.hits_ttl, shared_data=shared_data, termination_flag=cls.termination_requested)
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
                tcpdump_active_count = shared_data.tcpdump_active_ip
            # display
            print(f'{tcpdump_active_count} ip seen in the last {args.hits_ttl} seconds.')
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
