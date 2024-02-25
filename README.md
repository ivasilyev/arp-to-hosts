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

sudo mkdir -p -m 700 "/opt/arp-to-hosts"

cd "/opt/arp-to-hosts" || exit 1
sudo curl -fsSLO \
    "https://raw.githubusercontent.com/ivasilyev/arp-to-hosts/master/arp-to-hosts.py"

sudo chmod -R 700 "/opt/arp-to-hosts"

cd
```

## Check updated `hosts`

```shell script
cat /etc/hosts
```

## Example run in debug mode

```shell script
sudo python3 "/opt/arp-to-hosts/arp-to-hosts.py" \
    --logging 0 \
| tee "/tmp/arp-to-hosts.log" 2>&1

nano "/tmp/arp-to-hosts.log"
```

## View network interfaces

```shell script
ip addr show
```

## Run normally

```shell script
export HOSTS_FILE="/opt/pihole/data/hosts"

sudo python3 "/opt/arp-to-hosts/arp-to-hosts.py" \
    --logging 5 \
    --hosts "${HOSTS_FILE}" \
    --nic "ens33" \
    --suffix "home"

cat "${HOSTS_FILE}"
```

## Create system service

```shell script
echo Export variables
export TOOL_NAME="arp-to-hosts"
export UN="root"
export TOOL_DIR="/opt/${TOOL_NAME}/"
export TOOL_OUT_FILE="/opt/pihole/data/hosts"
export TOOL_BIN="/opt/arp-to-hosts/arp-to-hosts.py"
export TOOL_SCRIPT="${TOOL_DIR}${TOOL_NAME}.sh"
export TOOL_SERVICE="/etc/systemd/system/${TOOL_NAME}.service"



echo Create ${TOOL_NAME} routine script
cat <<EOF | sudo tee "${TOOL_SCRIPT}"
#!/usr/bin/env bash
# bash "${TOOL_SCRIPT}"
export TOOL_DIR="/opt/${TOOL_NAME}/"
export TOOL_BIN="${TOOL_BIN}"
export TOOL_OUT_FILE="/opt/pihole/data/hosts"

while true
    do
    python3 "\${TOOL_BIN}" \
        --logging 5 \
        --hosts "\${TOOL_OUT_FILE}" \
        --nic "ens33" \
        --suffix "home"

    # Dirty fix for a pretty hostname
    # sed -i -r "s/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ugly-hostname/\1 pretty-hostname ugly-hostname/g" "${TOOL_OUT_FILE}"
    sleep 1h

    done
EOF

sudo chmod a+x "${TOOL_SCRIPT}"
# nano "${TOOL_SCRIPT}"



echo Create ${TOOL_NAME} system service
cat <<EOF | sudo tee "${TOOL_SERVICE}"
[Unit]
Description=${TOOL_NAME}
Documentation=https://google.com
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${UN}
ExecReload=/usr/bin/env docker stop "${TOOL_NAME}"; /usr/bin/env kill -s SIGTERM \$MAINPID
ExecStart=/usr/bin/env bash "${TOOL_SCRIPT}"
SyslogIdentifier=${TOOL_NAME}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# nano "${TOOL_SERVICE}"



echo Activate ${TOOL_NAME} service
sudo systemctl daemon-reload
sudo systemctl enable "${TOOL_NAME}.service"
sudo systemctl restart "${TOOL_NAME}.service"
sleep 3
sudo systemctl status "${TOOL_NAME}.service"
```



## (Not recommended) Create and add `cron` rules

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
