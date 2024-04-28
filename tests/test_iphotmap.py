import pytest

from iphotmap.iphotmap import *


def test_find_cmd_from_env_path_existing():
    assert find_cmd_from_env_path('ls') == pathlib.Path('/usr/bin/ls')


def test_find_cmd_from_env_path_non_existing():
    name = 'xxxxxxxxxxxxxxxxxx'
    with pytest.raises(FileNotFoundError, match=rf'^{name} not found in .*$'):
        find_cmd_from_env_path(name)
