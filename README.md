# ip-hotmap

A curses-based ip hot-map display (uses tcpdump raw packets, and haproxy socket stats)

## Dev install

    sudo apt-get install -y python3-venv python3-setuptools python3-wheel
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements_dev.txt
    pip install -e .

In PyCharm : in settings, add/pick a local interpreter "with existing environment", so it uses `.venv`.
