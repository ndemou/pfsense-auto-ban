#!/usr/bin/env python3
"""
pf-filter-watch.py

This script watches the pfSense firewall log in real time and looks for blocked
incoming TCP connection attempts that match a specific set of pf rule IDs. When
it sees such an event, it extracts the source IP address and destination port,
writes a readable message to the console and to its own daily log file, and can
optionally add the source IP to a pfSense alias/table such as `nd_auto_ban`.

The main purpose is simple: detect hostile traffic that is already being blocked
by selected firewall rules and automatically feed the offending source IPs into
a dynamic block alias for later use by pfSense rules. This is useful when you
have tarpitted or honeytrap-style exposed ports, or when you want repeated
probes against specific WAN services to result in a broader ban. The script does
not create or edit pfSense firewall rules. Instead, it relies on the safer and
simpler pattern of using one existing pfSense alias/table and one or more normal
firewall rules that reference that alias.

How it works:
You are suposed to have created one rule in your WAN interface(s) that blocks
connections to ports that you don't use and are popular targets for bots (e.g.
ports 22,3389,8080,5900,...).
The script continuously follows `/var/log/filter.log`, similar to `tail -f`. For
each new log line, it checks whether the line is a blocked inbound IPv4 TCP
event and whether its rule ID matches one of the configured watched rule IDs. If
so, it checks whether the source IP is in the configured allow-list. Allowed IPs
are ignored. All other matching source IPs are reported, and if alias updates
are enabled, the script calls `pfctl -t <alias> -T add <ip>` to add the source
IP to the configured alias/table. Duplicate additions are harmless. The script
also handles filter.log rotation and reloads its JSON config automatically when
the config file changes.

Typical pfSense usage:
1. Create an alias for ports called `OnlyBotsTryThesePorts` and add ports
   that **you don't use** but are popular Bot targets. E.g.:
   22,23,2222,2323,3389,5900,7547,8291,8080,8443
2. Create a pfSense alias of type Host(s) or Network(s), for example
   `nd_auto_ban`. Leave it empty
3. Create a top firewall rule for every WAN interface. It should block
   traffic towards `OnlyBotsTryThesePorts`. Copy their rule IDs for latter.
4. Create another firewall rule per WAN **below** that one that blocks traffic
   with source IP address `nd_auto_ban`.
5. Put the rule IDs you copied into the JSON config file.
6. Put always-allowed source IPs if any in the JSON config file.
7. Run this script as root to test it.

Suggested file locations on pfSense:
- Script: `/usr/local/sbin/pf-filter-watch.py`
- Config: `/usr/local/etc/pf-filter-watch.json`
- Log output: `/var/log/pf-filter-watch.log`

A minimal installation usually looks like this:
- Save the script to `/usr/local/sbin/pf-filter-watch.py`
- Make it executable with `chmod 755 /usr/local/sbin/pf-filter-watch.py`
- Create `/usr/local/etc/pf-filter-watch.json`
- Test manually by running `/usr/local/sbin/pf-filter-watch.py`
- Confirm that matching blocked events are reported and that source IPs appear
  in `Diagnostics > Tables` for your chosen alias

Example config:

{
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

Notes and limitations:
- This script only processes IPv4 TCP block events.
- It does not currently support CIDR allow-lists, only individual IPs.
- It does not remove IPs from the alias; additions are runtime changes to the
  live PF table.

Examples:
- Run with the default config:
  `/usr/local/sbin/pf-filter-watch.py`
- Run with an alternate config:
  `/usr/local/sbin/pf-filter-watch.py /path/to/custom-config.json`

Recommended first test:
Expose one watched port, trigger a blocked connection from a test host that is
not in `allowed_ips`, and confirm all of the following:
- the script prints a readable detection message
- the message is written to `/var/log/pf-filter-watch.log`
- the source IP appears in `Diagnostics > Tables`
- a pfSense rule that references your alias blocks that source as intended
"""
import ipaddress
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time

DEFAULT_LOG_PATH = "/var/log/filter.log"
DEFAULT_CONFIG_PATH = "/usr/local/etc/pf-filter-watch.json"
DEFAULT_ALIAS_NAME = "nd_auto_ban"
DEFAULT_PFCTL_PATH = "/sbin/pfctl"
DEFAULT_APP_LOG_PATH = "/var/log/pf-filter-watch.log"


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    rule_ids = set(str(x) for x in cfg.get("rule_ids", []))
    allowed_ips = set(str(x) for x in cfg.get("allowed_ips", []))
    log_path = str(cfg.get("log_path", DEFAULT_LOG_PATH))
    alias_name = str(cfg.get("alias_name", DEFAULT_ALIAS_NAME))
    pfctl_path = str(cfg.get("pfctl_path", DEFAULT_PFCTL_PATH))
    app_log_path = str(cfg.get("app_log_path", DEFAULT_APP_LOG_PATH))
    add_to_alias = bool(cfg.get("add_to_alias", True))
    print_only = bool(cfg.get("print_only", False))
    poll_interval_seconds = float(cfg.get("poll_interval_seconds", 0.5))

    if not rule_ids:
        raise ValueError("config error: rule_ids is empty")

    for ip_text in allowed_ips:
        ipaddress.ip_address(ip_text)

    return {
        "rule_ids": rule_ids,
        "allowed_ips": allowed_ips,
        "log_path": log_path,
        "alias_name": alias_name,
        "pfctl_path": pfctl_path,
        "app_log_path": app_log_path,
        "add_to_alias": add_to_alias,
        "print_only": print_only,
        "poll_interval_seconds": poll_interval_seconds,
    }


def build_logger(log_path):
    logger = logging.getLogger("pf-filter-watch")
    logger.setLevel(logging.INFO)
    logger.handlers = []
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(message)s", "%b %d %H:%M:%S")

    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=6,
        encoding="utf-8",
        utc=False
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def parse_filterlog_line(line):
    if "filterlog" not in line:
        return None

    try:
        prefix, csv_part = line.split(": ", 1)
    except ValueError:
        return None

    fields = csv_part.rstrip("\r\n").split(",")

    if len(fields) < 22:
        return None

    try:
        rule_id = fields[3]
        action = fields[6]
        direction = fields[7]
        ipver = fields[8]
        protocol = fields[16]
        src_ip = fields[18]
        dst_port = fields[21]
    except IndexError:
        return None

    if action != "block":
        return None
    if direction != "in":
        return None
    if ipver != "4":
        return None
    if protocol != "tcp":
        return None

    timestamp = prefix[:15]

    return {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "src_ip": src_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "raw": line.rstrip("\r\n"),
    }


def open_for_follow(path):
    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    st = os.fstat(f.fileno())
    return f, st.st_ino


def add_ip_to_table(pfctl_path, table_name, ip_text):
    cmd = [pfctl_path, "-t", table_name, "-T", "add", ip_text]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = ((r.stdout or "") + (r.stderr or "")).strip().lower()

    if r.returncode != 0:
        raise RuntimeError(out or "pfctl add failed")

    if "1/1 addresses added" in out:
        return "added"
    if "0/1 addresses added" in out:
        return "already_present"

    return "unknown"


def safe_ip_text(ip_text):
    return str(ipaddress.ip_address(ip_text))


def follow_log(config_path):
    cfg = load_config(config_path)
    logger = build_logger(cfg["app_log_path"])

    f, current_inode = open_for_follow(cfg["log_path"])
    last_config_mtime = os.path.getmtime(config_path)

    logger.info(
        "Started. Watching %s, matching rule IDs: %s, always-allowed IPs: %s, alias: %s",
        cfg["log_path"],
        ", ".join(sorted(cfg["rule_ids"])),
        ", ".join(sorted(cfg["allowed_ips"])) if cfg["allowed_ips"] else "(none)",
        cfg["alias_name"]
    )

    seen_recent = set()

    while True:
        line = f.readline()

        if line:
            parsed = parse_filterlog_line(line)
            if parsed is not None:
                try:
                    src_ip = safe_ip_text(parsed["src_ip"])
                except ValueError:
                    logger.warning("Ignored line with invalid source IP: %s", parsed["raw"])
                    continue

                if parsed["rule_id"] not in cfg["rule_ids"]:
                    continue

                if src_ip in cfg["allowed_ips"]:
                    logger.info(
                        "Ignored allowed IP %s that matched watched rule %s on TCP port %s.",
                        src_ip,
                        parsed["rule_id"],
                        parsed["dst_port"]
                    )
                    continue

                key = (src_ip, parsed["dst_port"], parsed["rule_id"])
                if key in seen_recent:
                    continue

                seen_recent.add(key)

                base_message = (
                    "IP {0} tried TCP port {1} "
                    "and matched watched rule {2}."
                ).format(src_ip, parsed["dst_port"], parsed["rule_id"])

                if cfg["print_only"] or not cfg["add_to_alias"]:
                    logger.info("%s No alias update was requested.", base_message)
                else:
                    try:
                        result = add_ip_to_table(cfg["pfctl_path"], cfg["alias_name"], src_ip)

                        if result == "added":
                            logger.info(
                                "%s Added %s to alias %s.",
                                base_message,
                                src_ip,
                                cfg["alias_name"]
                            )
                        elif result == "already_present":
                            logger.info(
                                "%s IP %s was already present in alias %s.",
                                base_message,
                                src_ip,
                                cfg["alias_name"]
                            )
                        else:
                            logger.info(
                                "%s Attempted to add %s to alias %s. pfctl returned an unexpected success message.",
                                base_message,
                                src_ip,
                                cfg["alias_name"]
                            )
                    except Exception as exc:
                        logger.error(
                            "%s Failed to add %s to alias %s: %s",
                            base_message,
                            src_ip,
                            cfg["alias_name"],
                            exc
                        )
            continue

        if len(seen_recent) > 10000:
            seen_recent.clear()
            logger.info("Cleared in-memory duplicate suppression cache.")

        time.sleep(cfg["poll_interval_seconds"])

        try:
            new_config_mtime = os.path.getmtime(config_path)
            if new_config_mtime != last_config_mtime:
                old_log_path = cfg["app_log_path"]
                cfg = load_config(config_path)
                last_config_mtime = new_config_mtime

                if cfg["app_log_path"] != old_log_path:
                    logger = build_logger(cfg["app_log_path"])

                logger.info("Reloaded configuration from %s.", config_path)
        except Exception as exc:
            logger.warning("Could not reload configuration from %s: %s", config_path, exc)

        try:
            st = os.stat(cfg["log_path"])
            if st.st_ino != current_inode:
                f.close()
                f, current_inode = open_for_follow(cfg["log_path"])
                logger.info("Reopened %s after log rotation.", cfg["log_path"])
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("Could not check %s for rotation: %s", cfg["log_path"], exc)


def main():
    config_path = DEFAULT_CONFIG_PATH

    if len(sys.argv) > 2:
        print("usage: {0} [config.json]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(2)

    if len(sys.argv) == 2:
        config_path = sys.argv[1]

    try:
        follow_log(config_path)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print("fatal: {0}".format(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()