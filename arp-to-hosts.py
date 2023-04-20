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


def split_table(s: str, is_space_delimiter: bool = False):
    r = "[\t]+"
    if is_space_delimiter:
        r = "[\t ]+"
    o = list()
    for line in split_lines(s):
        if line.startswith("#"):
            row = [line]
        else:
            row = [re.sub("^[^#]+(#.*)", "", j.strip()) for j in re.split(r, line)]
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


def is_ip_valid(x: str):
    return (
        all(not x.startswith(i) for i in ["127.", "::1", "fe00:", "ff00:", "ff02:"])
        and len(re.findall("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", x)) > 0
    )


def validate_hostname(s):
    s = s.lower().strip()
    # .local conflicts with Multicast DNS
    if s.endswith(".lpcal"):
        return ""
    return re.sub("[_-]+", "-", s)


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
    o = go(f"/usr/sbin/arp-scan --interface=\"{nic}\" --localnet --plain --quiet")
    addresses = sorted_set([j for j in [i[0] for i in split_table(o)] if is_ip_valid(j)])
    return addresses


def nmblookup(ip: str):
    o = go(f"nmblookup -A {ip}")
    active_name_strings = [i for i in split_lines(o) if "<ACTIVE>" in i]
    for active_name_string in active_name_strings:
        name = re.findall("^([^ ]+)", active_name_string)[0]
        if len(name) > 0 and name not in ("MAC", "__MSBROWSE__"):
            return name
    return ""


def nslookup(ip: str):
    o = go(f"nslookup \"{ip}\"")
    for name_string in flatten_2d_list(split_table(o)):
        name = re.findall("name = ([^ ]+)", name_string)
        if len(name) > 0:
            return name[0].strip(" .")
    return ""


def arp_a(ip: str):
    o = go(f"/usr/sbin/arp -a \"{ip}\"")
    for name_string in split_lines(o):
        name = re.findall("(^[^ ]+)", name_string)
        if len(name) > 0:
            return name[0].strip(" .")
    return ""


def dig_x(ip: str):
    o = go(f"dig -x \"{ip}\"")
    for row_list in split_table(o):
        if len(row_list) < 4:
            continue
        if row_list[1] == "IN" and row_list[2] == "PTR":
            return row_list[3].strip(" .")
    return ""


def pick_hostname(ip: str):
    for func in (nmblookup, nslookup, arp_a, dig_x):
        name = func.__name__
        logging.info(f"Trying '{name}'")
        out = func(ip)
        if len(out) > 0 and out not in ("?", "_gateway"):
            logging.debug(f"Got hostname for IP address '{ip}' via '{name}'")
            return dict(ip=ip, hostname=out.lower())
    return dict()


def mp_queue(func, queue: list):
    with mp.Pool(min(len(queue), mp.cpu_count())) as p:
        out = p.map(func, queue)
        p.close()
        p.join()
    return out


def ip_route(dev: str):
    o = go(f"ip route get 1")
    split_lines(o)
    for line in split_lines(o):
        if f"dev {dev} " in line:
            name = re.findall("src ([^ ]+)", line)
            if len(name) > 0:
                return name[0].strip(" .")
    return ""


def get_self_hostname(*args, **kwargs):
    o = go(f"hostname --short")
    _hostname = o.split(" ")[0].strip()
    _ip = ip_route(*args, **kwargs)
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


def load_hosts(*args, **kwargs):
    o = split_table(load_string(*args, **kwargs), is_space_delimiter=True)
    logging.debug(f"Read {len(o)} lines")
    return o


def join_table(list_of_lists: list):
    return "\n".join(["\t".join([str(column) for column in row]) for row in list_of_lists]) + "\n"


def restart_dns():
    logging.info("Restart DNS")
    o = go("systemctl restart systemd-hostnamed").strip()
    if len(o) > 0:
        logging.warning(f"DNS restart attempt finished unexpectedly: '{o}'")


def get_logging_level():
    var = os.getenv("LOGGING_LEVEL")
    if var is not None and len(var) > 0 and hasattr(logging, var):
        val = getattr(logging, var)
        if isinstance(val, int) and val in [i * 10 for i in range(0, 6)]:
            return val
    return logging.ERROR


def parse_args():
    p = ArgumentParser(description="This tool scans the network for the hosts telling their hostnames "
                                   "and updates the system hosts file",
                       epilog="Make sure you're familiar with the naming standards, "
                              "e.g. RFC 2606, RFC 6761, RFC 6762 incl. Appendix G")
    p.add_argument("-n", "--nic", help="(Optional) Network interface", default="")
    p.add_argument("-s", "--suffix", help="(Optional) Default suffix", default="")
    ns = p.parse_args()
    return (
        ns.nic,
        ns.suffix
    )


if __name__ == '__main__':
    (
        input_nic,
        input_suffix
    ) = parse_args()

    logging.basicConfig(
        format=u"%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s",
        level=get_logging_level()
    )

    if is_nic_valid(input_nic):
        main_nic = input_nic
    else:
        main_nic = get_default_nic()

    parsed_ip_addresses = arp_scan(main_nic)

    raw_hostname_dicts = mp_queue(pick_hostname, parsed_ip_addresses)
    hostname_dicts = sorted([i for i in raw_hostname_dicts if "hostname" in i.keys()], key=lambda x: x.get("hostname"))
    hostname_dicts.append(get_self_hostname(main_nic))
    logging.debug(f"Parsed hostnames are '{hostname_dicts}'")

    main_suffix = check_suffix(input_suffix)

    logging.info(f"Add suffix '{main_suffix}' to {len(hostname_dicts)} discovered hostnames")
    for index in range(len(hostname_dicts)):
        hostname_dict = hostname_dicts[index]
        hostname_dict["hostnames"] = [hostname_dict["hostname"], "{}.{}".format(hostname_dict["hostname"], main_suffix)]
        if index == len(hostname_dicts) - 1:
            hostname_dict["hostnames"] = [hostname_dict["hostnames"][-1]]
        hostname_dict.pop("hostname")
        hostname_dicts[index] = hostname_dict

    table_append = [[i["ip"]] + i["hostnames"] for i in hostname_dicts]

    hosts_table = load_hosts(HOSTS_FILE)
    old_hosts_table_size = len(hosts_table)
    pop_count = 0
    for old_index in range(len(hosts_table)):
        new_index = old_index - pop_count
        hosts_entry = hosts_table[new_index]
        if not is_ip_valid(hosts_entry[0]):
            continue
        entry_hostnames = sorted(remove_empty_values([validate_hostname(i) for i in hosts_entry[1:]]), key=len)
        hosts_table[new_index] = [hosts_entry[0]] + entry_hostnames
        for hostname_dict in hostname_dicts:
            if hostname_dict["ip"] == hosts_entry or any(i in entry_hostnames for i in hostname_dict["hostnames"]):
                logging.debug(f"Remove entry: '{hosts_entry}'")
                hosts_table.pop(new_index)
                pop_count += 1
                break

    updating_entries_number = old_hosts_table_size - len(hosts_table)
    logging.info(f"{updating_entries_number} host entries to update, {len(table_append) - updating_entries_number} to add")

    backup_file = f"{HOSTS_FILE}.bak"
    if not os.path.exists(backup_file):
        copy2(HOSTS_FILE, backup_file)
        logging.info(f"Created backup: '{backup_file}'")

    new_hosts_content = join_table(hosts_table + table_append)
    dump_string(new_hosts_content, HOSTS_FILE)
    logging.info("Hosts update completed")
