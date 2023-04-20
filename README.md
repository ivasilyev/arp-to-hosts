# arp-to-hosts
Tool to manage system hosts based on the network environment

```text
usage: arp_to_hosts.py [-h] [-n NIC] [-s SUFFIX]

This tool scans the network for the hosts telling their hostnames and updates the system hosts file

optional arguments:
  -h, --help            show this help message and exit
  -n NIC, --nic NIC     (Optional) Network interface
  -s SUFFIX, --suffix SUFFIX
                        (Optional) Default suffix

Make sure you're familiar with the naming standards, e.g. RFC 2606, RFC 6761, RFC 6762 incl. Appendix G
```


## Setup

```shell script
sudo apt-get update -y

sudo apt-get install -y \
    arp-scan \
    bind9-dnsutils \
    curl \
    iproute2 \
    net-tools \
    python3 \
    samba-common-bin

sudo mkdir -p -m 755 "/opt/arp-to-hosts"

cd "/opt/arp-to-hosts" && \
sudo curl -fsSLO \
    "https://raw.githubusercontent.com/ivasilyev/arp-to-hosts/master/arp-to-hosts.py"
cd
```

## Check updated `hosts`

```shell script
cat /etc/hosts
```

## Run in debug mode

```shell script
LOGGING_LEVEL="DEBUG" python3 "/opt/arp-to-hosts/arp-to-hosts.py"
```

## Add cron rule

```shell script
sudo crontab -e
```
```text
# Update hosts every midnight
0 0 * * * "/usr/bin/python3" "/opt/arp-to-hosts/arp-to-hosts.py" > /dev/null 2>&1 &
```
```shell script
sudo crontab -l
```
