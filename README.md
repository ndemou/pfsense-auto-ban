# What the script does

This script will automatically ban IPs that try to connect to honeypot ports (ports that are popular targets for malware/bots/hackers but that you don't have open to the Internet).

It logs to `/var/log/pf-filter-watch.log`.

You can permit-list IPs in `/usr/local/etc/pf-filter-watch.json` so that they are never banned.

You need to create a two firewall rules and two aliases to use it.

# Setup guide for nd_auto_ban with pf-filter-watch.py

## 1) Prepare pfSense firewall objects

In **Firewall > Aliases** create:

- `OnlyBotsTryThesePorts` as a *port alias* with ports you **do not expose to the Internet** but that bots love to probe, for example:
  `22,23,445,2222,2323,3389,5900,7547,8291,8080,8443`
- `nd_auto_ban` as an empty *Host(s) or Network(s)* alias

In **Firewall > Rules > WAN**:

- add a **top** rule that **blocks and logs** traffic to `OnlyBotsTryThesePorts`. Note the id of the rule ("Tracking ID"). You'll need it latter.
- add another rule **below it** that blocks traffic from source `nd_auto_ban`.

**Repeat if** you have more than one WAN interface.

Apply changes.



## 2) Install Python (**you may need to adjust the minor version**)

```sh
pkg search python

# EXAMPLE OUTPUT:
# python311-3.11.11              Interpreted object-oriented programming language

pkg install python311
#                  ^^ ADJUST MINOR VERSION IF NECESSARY

ln -s /usr/local/bin/python3.11 /usr/local/bin/python3
#                            ^^ ADJUST MINOR VERSION IF NECESSARY
```

## 3) Put the watcher script in place

Save the Python script as:

```text
/usr/local/sbin/pf-filter-watch.py
```

Then make it executable:

```sh
chmod 755 /usr/local/sbin/pf-filter-watch.py
```

## 4) Create the config file

```sh
mkdir -p /usr/local/etc
python3 - <<'PY'
from pathlib import Path
Path('/usr/local/etc/pf-filter-watch.json').write_text(r'''{
  "log_path": "/var/log/filter.log",
  "rule_ids": [
    "1776328730",
    "1776328716"
  ],
  "allowed_ips": [
    "1.2.3.4"
  ],
  "alias_name": "nd_auto_ban",
  "pfctl_path": "/sbin/pfctl",
  "app_log_path": "/var/log/pf-filter-watch.log",
  "add_to_alias": true,
  "print_only": false,
  "poll_interval_seconds": 0.5
}
''', encoding='utf-8')
PY
```

Replace:

* `rule_ids` with your actual pfSense rule IDs
* `allowed_ips` with any IPs that must never be auto-banned

## 5) Create the startup script

```sh
python3 - <<'PY'
from pathlib import Path
Path('/usr/local/etc/rc.d/pf_filter_watch.sh').write_text(r'''#!/bin/sh

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

if /usr/bin/pgrep -f '/usr/local/sbin/pf-filter-watch.py' >/dev/null 2>&1; then
    exit 0
fi

nohup /usr/local/sbin/pf-filter-watch.py >/dev/null 2>&1 </dev/null &
exit 0
''', encoding='utf-8')
PY

chmod 755 /usr/local/etc/rc.d/pf_filter_watch.sh
```

## 6) Start it now

```sh
/usr/local/etc/rc.d/pf_filter_watch.sh
```

## 7) Confirm it is running

```sh
pgrep -af pf-filter-watch
tail -20 /var/log/pf-filter-watch.log
```

## 8) **IF YOU CAN REBOOT**, do so, to confirm auto-start

```sh
reboot
```

After reconnecting:

```sh
pgrep -af pf-filter-watch
tail -20 /var/log/pf-filter-watch.log
```

## Everyday use

You can review and remove baned IPs from `Diagnostics` > `Tables` > Select `nd_auto_ban` from the list:
<img width="658" height="484" alt="image" src="https://github.com/user-attachments/assets/297be5c0-aadf-4e46-8310-df858bd0f8fd" />

You can permit list some IP by adding it to `/usr/local/etc/pf-filter-watch.json`.

You can monitor the logs:
```sh
# tail -f /var/log/pf-filter-watch.log
May 05 13:34:48 Started. Watching /var/log/filter.log, matching rule IDs: 1776328716, 1776328730, always-allowed IPs: 1.2.3.4, alias: nd_auto_ban
May 05 13:34:55 IP 213.5.70.12 tried TCP port 23 and matched watched rule 1776328730. IP 213.5.70.12 was already present in alias nd_auto_ban.
May 05 13:35:11 IP 45.148.10.230 tried TCP port 22 and matched watched rule 1776328716. Added 45.148.10.230 to alias nd_auto_ban.
May 05 13:35:40 IP 38.9.184.151 tried TCP port 23 and matched watched rule 1776328716. Added 38.9.184.151 to alias nd_auto_ban.
```

## Files used

* Script: `/usr/local/sbin/pf-filter-watch.py`
* Config: `/usr/local/etc/pf-filter-watch.json`
* Runtime log: `/var/log/pf-filter-watch.log`
* Startup hook: `/usr/local/etc/rc.d/pf_filter_watch.sh`
