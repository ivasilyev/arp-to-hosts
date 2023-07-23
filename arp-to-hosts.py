#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
from shutil import copy2
import multiprocessing as mp
from subprocess import getoutput
from argparse import ArgumentParser


HOSTS_FILE = "/etc/hosts"
DEFAULT_SUFFIX = "lan"


def join_lines(s: str):
    return re.sub("[\r\n ]+", " ", s)


def go(cmd: str):
    o = getoutput(cmd)
    logging.debug(f"Ran command: '{join_lines(cmd)}' with the output: '{o}'")
    return o


def split_lines(s: str):
    return [i.strip() for i in re.split("[\r\n]+", s)]


def split_columns(s: str, is_space_delimiter: bool = False):
    r = "[\t]+"
    if is_space_delimiter:
        r = "[\t ]+"
    return [i.strip() for i in re.split(r, s)]


def split_table(s: str, is_space_delimiter: bool = False):
    o = list()
    for line in split_lines(s):
        row = [re.sub("^[^#]+(#.*)", "", i) for i in split_columns(line, is_space_delimiter)]
        o.append(row)
    return o


def sorted_set(x: list):
    return sorted(set(x))


def flatten_2d_list(x: list):
    return [j for i in x for j in i]


def check_suffix(s: str):
    s = s.strip(" ,.")
    if len(s) == 0 or s in ("local",):
        logging.info(f"Invalid suffix: '{s}', use default instead: '{DEFAULT_SUFFIX}'")
        return DEFAULT_SUFFIX
    return s


def remove_empty_values(x: list):
    return [i for i in x if len(i) > 0]


def is_ip_loopback(s: str):
    return any(s.startswith(i) for i in ["127.", "::1", "fe00:", "ff00:", "ff02:"])


def is_ip_valid(s: str):
    return (
        len(s) > 0
        and not is_ip_loopback(s)
        and len(re.findall("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", s)) > 0
    )


def is_hosts_line_valid(s: str):
    return (
        len(s) == 0
        or is_ip_loopback(s)
        or is_ip_valid(s)
        or s.startswith("#")
        or s.startswith(";")
    )


def is_hostname_valid(s: str):
    return (
        s is not None
        and len(s) > 0
        and len(re.findall("[^A-Za-z0-9\.\-_]+", s)) == 0
        # .local conflicts with Multicast DNS
        and not s.endswith(".local")
        and s not in ("*", "?", "_gateway")
    )


def validate_hostname(s: str):
    if is_hostname_valid(s):
        s = s.lower().strip()
        return re.sub("[ _-]+", "-", s)
    return ""


def is_nic_valid(s: str):
    o = go("ls /sys/class/net")
    nics = remove_empty_values(split_lines(o))
    if len(s) > 0:
        if s in nics:
            return True
        logging.warning(f"Invalid NIC: '{s}', reset to default")
    return False


def get_default_nic():
    o = go("ip route show default 0.0.0.0/0")
    default_line = [
        i for i in split_lines(o)
        if i.startswith("default")
    ][0]
    out = re.findall("dev ([^ ]+)", default_line)[0]
    logging.info(f"Got the default interface: '{out}'")
    return out


def arp_scan(nic: str):
    o = go(f"/usr/sbin/arp-scan --interface={nic} --localnet --plain --quiet")
    addresses = sorted_set([j for j in [i[0] for i in split_table(o)] if is_ip_valid(j)])
    logging.debug(f"'arp-scan' returned {len(addresses)} adresses")
    return addresses


def nmblookup(ip: str):
    o = go(f"nmblookup -A {ip}")
    active_name_strings = [i for i in split_lines(o) if "<ACTIVE>" in i and "<GROUP>" not in i]
    for active_name_string in active_name_strings:
        name = re.findall("^([^ ]+)", active_name_string)[0]
        if len(name) > 0 and name not in ("MAC", "__MSBROWSE__"):
            logging.debug(f"'nmblookup' returned '{name}'")
            return name
    return ""


def nslookup(ip: str):
    o = go(f"nslookup \"{ip}\"")
    for name_string in flatten_2d_list(split_table(o)):
        name = re.findall("name = ([^ ]+)", name_string)
        if len(name) > 0:
            out = name[0].strip(" .")
            logging.debug(f"'nslookup' returned '{out}'")
            return out
    return ""


def arp_a(ip: str):
    o = go(f"/usr/sbin/arp -a \"{ip}\"")
    for name_string in split_lines(o):
        name = re.findall("(^[^ ]+)", name_string)
        if len(name) > 0:
            out = name[0].strip(" .")
            logging.debug(f"'arp -a' returned '{out}'")
            return out
    return ""


def dig_x(ip: str):
    o = go(f"dig -x \"{ip}\"")
    for row_list in split_table(o):
        if len(row_list) < 4:
            continue
        if row_list[1] == "IN" and row_list[2] == "PTR":
            out = row_list[3].strip(" .")
            logging.debug(f"'dig -x' returned '{out}'")
            return out
    return ""


def pick_hostname(ip: str):
    if not is_ip_valid(ip):
        return dict()
    for func in (nmblookup, nslookup, arp_a, dig_x):
        name = func.__name__
        logging.info(f"Trying '{name}'")
        hostname = validate_hostname(func(ip))
        if len(hostname) > 0:
            logging.debug(f"Got hostname for IP address '{ip}' via '{name}': '{hostname}'")
            return dict(ip=ip, hostname=hostname)
    return dict()


def mp_queue(func, queue: list):
    with mp.Pool(min(len(queue), mp.cpu_count())) as p:
        out = p.map(func, queue)
        p.close()
        p.join()
    return out


def get_self_hostname(dev: str):
    o = go(f"hostname --short")
    _hostname = validate_hostname(o.split(" ")[0].strip())
    _ip = go(f"ip addr show dev {dev} | grep -oP '(?<=inet )[0-9.]+(?=/)'")
    return dict(hostname=_hostname, ip=_ip)


def load_string(file: str):
    logging.debug(f"Read file: '{file}'")
    with open(file, mode="r", encoding="utf-8") as f:
        o = f.read()
        f.close()
    return o


def dump_string(s: str, file: str):
    logging.debug(f"Write file: '{file}'")
    with open(file, mode="w", encoding="utf-8") as f:
        f.write(s)
        f.close()


def load_hosts(file: str):
    o = split_lines(load_string(file))
    out = [i for i in o if is_hosts_line_valid(i)]
    logging.debug(f"Read {len(out)} lines")
    return out


def join_table(list_of_lists: list):
    return "\n".join(["\t".join([str(column) for column in row]) for row in list_of_lists]) + "\n"


def flush_dns():
    logging.info("Flush DNS caches")
    o = go("resolvectl flush-caches").strip()
    if len(o) > 0:
        logging.warning(f"DNS cache flush attempt finished unexpectedly: '{o}'")
    logging.info("Restart DNS")
    o = go("systemctl restart systemd-hostnamed").strip()
    if len(o) > 0:
        logging.warning(f"DNS restart attempt finished unexpectedly: '{o}'")


def get_logging_level():
    var = os.getenv("LOGGING_LEVEL", None)
    if (
        var is not None
        and len(var) > 0
        and hasattr(logging, var)
    ):
        val = getattr(logging, var)
        if isinstance(val, int) and val in [i * 10 for i in range(0, 6)]:
            return val
    return logging.ERROR


def validate_new_hostnames(dicts: list):
    out = list()
    for d in dicts:
        if (
            "hostname" in d.keys()
            and is_ip_valid(d.get("ip"))
            and is_hostname_valid(d.get("hostname"))
        ):
            out.append(d)
    return sorted(out, key=lambda x: x.get("ip"))


def process_hosts_table(table: list, hostnames: dict, suffix: str):
    suffix = f".{suffix}"
    hostnames_with_suffixes = dict()
    for ip, hostname in hostnames.items():
        if not hostname.endswith(suffix):
            hostname = f"{hostname}{suffix}"
        hostnames_with_suffixes[ip] = hostname
    new_hostnames = list(hostnames.values()) + list(hostnames_with_suffixes.values())
    out_lines = list()
    for line in table:
        columns = remove_empty_values(split_columns(line, is_space_delimiter=True))
        if len(columns) == 0:
            out_lines.append([line])
            continue
        ip = columns[0]
        if not is_ip_valid(ip):
            out_lines.append([line])
            continue
        hostnames = [i for i in columns[1:] if i not in new_hostnames]
        if ip in hostnames_with_suffixes.keys():
            hostnames = [hostnames_with_suffixes.pop(ip)]
        out_lines.append([ip, *hostnames])
    logging.debug(f"New host names to add: '{hostnames_with_suffixes}'")
    extend_hostnames = list(hostnames_with_suffixes.items())
    out_lines.extend(extend_hostnames)
    return out_lines


def parse_args():
    p = ArgumentParser(description="This tool scans the network for the hosts telling their hostnames "
                                   "and updates the system hosts file",
                       epilog="Make sure you're familiar with the naming standards, "
                              "e.g. RFC 2606, RFC 6761, RFC 6762 incl. Appendix G")
    p.add_argument("-f", "--flush", help="(Optional) Flush DNS records", action="store_true")
    p.add_argument("-n", "--nic", help="(Optional) Network interface", default="")
    p.add_argument("-s", "--suffix", help="(Optional) Default suffix", default=DEFAULT_SUFFIX)
    ns = p.parse_args()
    return (
        ns.flush,
        ns.nic,
        ns.suffix,
    )


if __name__ == '__main__':
    (
        input_is_flush,
        input_nic,
        input_suffix,
    ) = parse_args()

    logger = logging.getLogger()
    logger.setLevel(get_logging_level())
    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter(
        u"%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s")
    )
    logger.addHandler(stream)

    if input_is_flush:
        flush_dns()

    if is_nic_valid(input_nic):
        main_nic = input_nic
    else:
        main_nic = get_default_nic()

    main_suffix = check_suffix(input_suffix)

    parsed_ip_addresses = arp_scan(main_nic)

    raw_hostname_dicts = mp_queue(pick_hostname, parsed_ip_addresses)

    hostname_dicts = raw_hostname_dicts + [get_self_hostname(main_nic)]
    hostname_dicts = validate_new_hostnames(hostname_dicts)
    hostname_dict = {i["ip"]: i["hostname"] for i in hostname_dicts}
    logging.debug(f"Parsed hostnames are '{hostname_dict}'")

    new_hosts_lines = process_hosts_table(
        table=load_hosts(HOSTS_FILE),
        suffix=main_suffix,
        hostnames=hostname_dict,
    )

    backup_file = f"{HOSTS_FILE}.bak"
    if not os.path.exists(backup_file):
        copy2(HOSTS_FILE, backup_file)
        logging.info(f"Created backup: '{backup_file}'")

    new_hosts_content = join_table(new_hosts_lines)
    dump_string(new_hosts_content, HOSTS_FILE)
    logging.info("Hosts update completed")
