import pytest

from iphotmap.iphotmap import *


def test_find_cmd_from_env_path_existing():
    assert find_cmd_from_env_path('ls') == pathlib.Path('/usr/bin/ls')


def test_find_cmd_from_env_path_non_existing():
    name = 'xxxxxxxxxxxxxxxxxx'
    with pytest.raises(FileNotFoundError, match=rf'^{name} not found in .*$'):
        find_cmd_from_env_path(name)

@pytest.mark.parametrize("test_input, expected", [
    ('IP 172.21.11.114.58744 > 172.21.0.1.53: UDP, length 43', ('172.21.11.114', '172.21.0.1')),
    ('IP 172.21.0.1.5353 > 224.0.0.251.5353: UDP, length 50', ('172.21.0.1', '224.0.0.251')),
    ('IP 172.21.11.114.49600 > 185.199.108.133.443: tcp 0', ('172.21.11.114', '185.199.108.133')),
    ('IP 172.21.11.114 > 145.24.145.63: ICMP echo request, id 40264, seq 1, length 64', ('172.21.11.114', '145.24.145.63')),
    ('IP 145.24.145.63 > 172.21.11.114: ICMP echo reply, id 40264, seq 1, length 64', ('145.24.145.63', '172.21.11.114')),
    ('IP6 fe80::79a9:54c5:b048:a33d.5353 > ff02::fb.5353: UDP, length 50', ('fe80::79a9:54c5:b048:a33d', 'ff02::fb')),
    ('IP 172.21.0.1.53 > 172.21.11.114.34876: UDP, length 93', ('172.21.0.1', '172.21.11.114')),
    ('ARP, Request who-has 172.21.0.1 tell 172.21.11.114, length 28', ('172.21.0.1', '172.21.11.114')),
    ('lo    In  IP 127.0.0.1.49018 > 127.0.0.1.5990: tcp 0', ('127.0.0.1', '127.0.0.1')),
    ('eth0  Out IP 172.21.11.114.60472 > 172.21.0.1.53: UDP, length 44', ('172.21.11.114', '172.21.0.1')),
    ('eth0  In  IP 172.21.0.1.53 > 172.21.11.114.60472: UDP, length 93', ('172.21.0.1', '172.21.11.114')),
    ('eth0  Out IP 172.21.11.114 > 145.24.145.63: ICMP echo request, id 38818, seq 1, length 64', ('172.21.11.114', '145.24.145.63')),
    ('eth0  In  IP 145.24.145.63 > 172.21.11.114: ICMP echo reply, id 38818, seq 1, length 64', ('145.24.145.63', '172.21.11.114')),
    ('eth0  In  ARP, Request who-has 172.21.11.114 (00:15:5d:75:4e:94) tell 172.21.0.1, length 28', ('172.21.11.114', '172.21.0.1')),
    ('eth0  Out ARP, Reply 172.21.11.114 is-at 00:15:5d:75:4e:94, length 28', ('172.21.11.114',)),
    ('eth0  M   IP6 fe80::79a9:54c5:b048:a33d.5353 > ff02::fb.5353: UDP, length 48', ('fe80::79a9:54c5:b048:a33d', 'ff02::fb')),
])
def test_tcpdump_re_address(test_input, expected):
    assert TcpdumpThread.addresses_from_line(test_input) == expected
