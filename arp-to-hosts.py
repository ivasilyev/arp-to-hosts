#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
from shutil import copy2
import multiprocessing as mp
from subprocess import getoutput
from argparse import ArgumentParser


DEFAULT_HOSTS_FILE = "/etc/hosts"
DEFAULT_SUFFIX = "lan"


def join_lines(s: str):
    return re.sub("[\r\n ]+", " ", s)


def go(cmd: str):
    o = getoutput(cmd)
    logger.debug(f"Ran command: '{join_lines(cmd)}' with the output: '{o}'")
    return o


def split_lines(s: str):
    return [i.strip() for i in re.split("[\r\n]", s)]


def split_columns(s: str, is_space_delimiter: bool = False):
    s = s.strip()
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
        logger.info(f"Invalid suffix: '{s}', use default instead: '{DEFAULT_SUFFIX}'")
        s = DEFAULT_SUFFIX
    return f".{s}"


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
        # .local conflicts with Multicast DNS
        and not s.endswith(".local")
        and all(i not in s for i in ["*", "?", "_gateway"])
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
        logger.warning(f"Invalid NIC: '{s}', reset to default")
    return False


def get_default_nic():
    o = go("ip route show default 0.0.0.0/0")
    lines = remove_empty_values(split_lines(o))
    default_line = [
        i for i in lines
        if i.startswith("default")
    ][0]
    out = re.findall("dev ([^ ]+)", default_line)[0]
    logger.info(f"Got the default interface: '{out}'")
    return out


def arp_scan(nic: str):
    o = go(f"/usr/sbin/arp-scan --interface={nic} --localnet --plain --quiet")
    addresses = sorted_set([j for j in [i[0] for i in split_table(o)] if is_ip_valid(j)])
    logger.debug(f"'arp-scan' returned {len(addresses)} adresses")
    return addresses


def nmblookup(ip: str):
    o = go(f"nmblookup -A {ip}")
    lines = remove_empty_values(split_lines(o))
    active_name_strings = [i for i in lines if "<ACTIVE>" in i and "<GROUP>" not in i]
    for active_name_string in active_name_strings:
        name = re.findall("^([^ ]+)", active_name_string)[0]
        if (
            len(name) > 0
            and name not in ("MAC", "__MSBROWSE__")
            and len(re.findall("<(.+)>", name)) == 0
            and os.getenv("HOST_SCAN_WORKGROUP", "WORKGROUP") not in name
        ):
            logger.debug(f"'nmblookup' returned '{name}'")
            return name
    return ""


def nslookup(ip: str):
    o = go(f"nslookup \"{ip}\"")
    for name_string in flatten_2d_list(split_table(o)):
        name = re.findall("name = ([^ ]+)", name_string)
        if len(name) > 0:
            out = name[0].strip(" .")
            logger.debug(f"'nslookup' returned '{out}'")
            return out
    return ""


def arp_a(ip: str):
    o = go(f"/usr/sbin/arp -a \"{ip}\"")
    lines = remove_empty_values(split_lines(o))
    for name_string in lines:
        name = re.findall("(^[^ ]+)", name_string)
        if len(name) > 0:
            out = name[0].strip(" .")
            logger.debug(f"'arp -a' returned '{out}'")
            return out
    return ""


def dig_x(ip: str):
    o = go(f"dig -x \"{ip}\"")
    for row_list in split_table(o):
        if len(row_list) < 4:
            continue
        if row_list[1] == "IN" and row_list[2] == "PTR":
            out = row_list[3].strip(" .")
            logger.debug(f"'dig -x' returned '{out}'")
            return out
    return ""


def pick_hostname(ip: str):
    if not is_ip_valid(ip):
        return dict()
    for func in (nmblookup, nslookup, arp_a, dig_x):
        name = func.__name__
        logger.info(f"Trying '{name}'")
        hostname = validate_hostname(func(ip))
        if len(hostname) > 0:
            logger.debug(f"Got hostname for IP address '{ip}' via '{name}': '{hostname}'")
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
    _hostname = o.split(" ")[0].strip()
    _ip = go(f"ip addr show dev {dev} | grep -oP '(?<=inet )[0-9.]+(?=/)'")
    return dict(hostname=_hostname, ip=_ip)


def load_string(file: str):
    logger.debug(f"Read file: '{file}'")
    with open(file, mode="r", encoding="utf-8") as f:
        o = f.read()
        f.close()
    return o


def dump_string(s: str, file: str):
    logger.debug(f"Write file: '{file}'")
    with open(file, mode="w", encoding="utf-8") as f:
        f.write(s)
        f.close()


def load_hosts(file: str):
    o = split_lines(load_string(file))
    out = [i for i in o if is_hosts_line_valid(i)]
    logger.debug(f"Read {len(out)} lines")
    return out


def join_table(list_of_lists: list, delimiter: str = "\t"):
    return "\n".join([delimiter.join([str(column) for column in row]) for row in list_of_lists]) + "\n"


def flush_dns():
    logger.info("Flush DNS caches")
    o = go("resolvectl flush-caches").strip()
    if len(o) > 0:
        logger.warning(f"DNS cache flush attempt finished unexpectedly: '{o}'")
    logger.info("Restart DNS")
    o = go("systemctl restart systemd-hostnamed").strip()
    if len(o) > 0:
        logger.warning(f"DNS restart attempt finished unexpectedly: '{o}'")


def validate_new_hostnames(dicts: list):
    out = list()
    for d in dicts:
        if (
            "hostname" in d.keys()
            and is_ip_valid(d.get("ip"))
        ):
            hostname = validate_hostname(d.get("hostname"))
            if is_hostname_valid(hostname):
                out.append(dict(ip=d.get("ip"), hostname=hostname))
    return sorted(out, key=lambda x: x.get("ip"))


def get_updating_hostname_entry(s: str, suffix: str) -> list:
    o = [s]
    if not s.endswith(suffix):
        o.append(f"{s}{suffix}")
    return o


def process_hosts_table(old_hosts: list, new_hosts: dict, suffix: str) -> list:
    hosts = list(old_hosts)
    new_hosts = dict(new_hosts)
    for hosts_file_line_idx in range(len(hosts)):
        hosts_file_line = hosts[hosts_file_line_idx]
        # Update the host entries first
        if len(hosts_file_line) > 1:
            host_ip = hosts_file_line[0]
            new_host_entry = new_hosts.get(host_ip)
            if new_host_entry is not None:
                logging.debug(f"Update the existing host entry: '{host_ip} {new_host_entry}'")
                hosts[hosts_file_line_idx] = [host_ip] + get_updating_hostname_entry(
                    new_host_entry, suffix
                )
                _ = new_hosts.pop(host_ip)
    # Append if new entries are present
    for host_ip, new_host_entry in new_hosts.items():
        logging.debug(f"Append the new host entry: '{host_ip} {new_host_entry}'")
        new_host_columns = [host_ip] + sorted(set(get_updating_hostname_entry(new_host_entry, suffix)), key=len)
        hosts.append(new_host_columns)
    return hosts


def get_hosts_file_stub():
    return """127.0.0.1 localhost
127.0.1.1 {}

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

""".format(go("hostname"))


def parse_args():
    p = ArgumentParser(description="This tool scans the network for the hosts telling their hostnames "
                                   "and updates the system hosts file",
                       epilog="Make sure you're familiar with the naming standards, "
                              "e.g. RFC 2606, RFC 6761, RFC 6762 incl. Appendix G")
    p.add_argument(
        "-f",
        "--flush",
        help="(Optional) Flush DNS records",
        action="store_true"
    )
    p.add_argument(
        "-l",
        "--logging",
        help="(Optional) Logging level",
        type=int,
        choices=range(0, 6),
        default=5
    )
    p.add_argument(
        "-i",
        "--nic",
        help="(Optional) Network interface",
        default=""
    )
    p.add_argument(
        "-s",
        "--suffix",
        help="(Optional) Default suffix",
        default=DEFAULT_SUFFIX
    )
    p.add_argument(
        "-o",
        "--hosts",
        help=f"(Optional) Hosts file, default: '{DEFAULT_HOSTS_FILE}'",
        default=DEFAULT_HOSTS_FILE
    )
    ns = p.parse_args()
    return (
        ns.flush,
        ns.logging * 10,
        ns.nic,
        ns.suffix,
        ns.hosts,
    )


if __name__ == '__main__':
    (
        input_is_flush,
        input_logging_level,
        input_nic,
        input_suffix,
        input_hosts_file,
    ) = parse_args()

    logger = logging.getLogger()
    logger.setLevel(input_logging_level)
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
    if len(parsed_ip_addresses) == 0:
        raise ValueError("No reachable IP addresses discovered")

    raw_hostname_dicts = mp_queue(pick_hostname, parsed_ip_addresses)

    hostname_dicts = raw_hostname_dicts + [get_self_hostname(main_nic)]

    hostname_dicts = validate_new_hostnames(hostname_dicts)
    new_hostname_dict = {i["ip"]: i["hostname"] for i in hostname_dicts}
    logger.debug(f"Parsed hostnames are '{new_hostname_dict}'")

    if not os.path.exists(input_hosts_file):
        os.makedirs(os.path.dirname(input_hosts_file), exist_ok=True)
        dump_string(get_hosts_file_stub(), input_hosts_file)

    hosts_file_lines = split_table(load_string(input_hosts_file), True)

    if len([i for i in hosts_file_lines if len(i) > 0 and i[0] == "127.0.0.1"]) == 0:
        hosts_file_lines = split_table(get_hosts_file_stub()) + hosts_file_lines
    updated_hosts_lines = process_hosts_table(hosts_file_lines, new_hostname_dict, main_suffix)

    backup_file = f"{input_hosts_file}.bak"
    if not os.path.exists(backup_file):
        copy2(input_hosts_file, backup_file)
        logger.info(f"Created backup: '{backup_file}'")

    new_hosts_content = join_table(updated_hosts_lines, " ")
    dump_string(new_hosts_content, input_hosts_file)
    logger.info("Hosts update completed")

    if input_is_flush:
        flush_dns()
