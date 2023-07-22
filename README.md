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

sudo chmod -R 755 "/opt/arp-to-hosts"

cd
```

## Check updated `hosts`

```shell script
cat /etc/hosts
```

## Run in debug mode

```shell script
export LOGGING_LEVEL="DEBUG"
sudo python3 "/opt/arp-to-hosts/arp-to-hosts.py" \
| tee "/tmp/arp-to-hosts.log" 2>&1
```

## View network interfaces

```shell script
ip addr show
```

## Create and add `cron` rules

```shell script
NICS="$(
    ip route show default 0.0.0.0/0 \
    | awk '{ print $5 }'
)"

while IFS= read -r LINE
    do 
    echo "
    0 15 * * * \"/usr/bin/python3\" \"/opt/arp-to-hosts/arp-to-hosts.py\" --nic \"${LINE}\" --suffix \"${LINE}\" > /dev/null 2>&1
    " \
    | sed 's/^[ \t]*//;s/[ \t]*$//';
    done \
<<< "${NICS}"

sudo crontab -e
```
```shell script
sudo crontab -l
```
