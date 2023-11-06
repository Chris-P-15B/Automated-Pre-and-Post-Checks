#!/usr/bin/env python3

"""
Copyright (c) 2019 - 2022, Chris Perkins
Licence: BSD 3-Clause

Portions of this code from get_routing_table.py v2.0, (c) Jarmo Pietiläinen 2013 - 2014, http://z0b.kapsi.fi/networking.php
& used under the zlib/libpng licence.
IP address sorting courtesy of https://www.python4networkengineers.com/posts/how_to_sort_ip_addresses_with_python/

To Do:
Add IPv6 support.
"""

import time
import socket
import ipaddress
import random
import threading
import pysnmp
import subprocess
from pysnmp.entity.rfc3413.oneliner import cmdgen


# Subnet mask -> CIDR prefix length lookup table
subnet_masks = {
    "128.0.0.0": "1",
    "192.0.0.0": "2",
    "224.0.0.0": "3",
    "240.0.0.0": "4",
    "248.0.0.0": "5",
    "252.0.0.0": "6",
    "254.0.0.0": "7",
    "255.0.0.0": "8",
    "255.128.0.0": "9",
    "255.192.0.0": "10",
    "255.224.0.0": "11",
    "255.240.0.0": "12",
    "255.248.0.0": "13",
    "255.252.0.0": "14",
    "255.254.0.0": "15",
    "255.255.0.0": "16",
    "255.255.128.0": "17",
    "255.255.192.0": "18",
    "255.255.224.0": "19",
    "255.255.240.0": "20",
    "255.255.248.0": "21",
    "255.255.252.0": "22",
    "255.255.254.0": "23",
    "255.255.255.0": "24",
    "255.255.255.128": "25",
    "255.255.255.192": "26",
    "255.255.255.224": "27",
    "255.255.255.240": "28",
    "255.255.255.248": "29",
    "255.255.255.252": "30",
    "255.255.255.254": "31",
    "255.255.255.255": "32",
}


def mask_to_prefix(mask):
    """Subnet mask -> prefix length, returns 0 if invalid/zero"""
    return subnet_masks.get(mask, 0)


def extract_ip_from_oid(oid):
    """Given a dotted OID string, this extracts an IPv4 address from the end of it (i.e. the last four decimals)"""
    return ".".join(oid.split(".")[-4:])


def ping(server="example.com", count=1, wait_sec=1):
    """Linux ping command passthru"""
    cmd = "ping -c {} -W {} {}".format(count, wait_sec, server).split(" ")
    try:
        output = subprocess.check_output(cmd).decode().strip()
        lines = output.split("\n")
        total = lines[-2].split(",")[3].split()[1]
        loss = lines[-2].split(",")[2].split()[0]
        timing = lines[-1].split()[3].split("/")
        return {
            "type": "rtt",
            "min": timing[0],
            "avg": timing[1],
            "max": timing[2],
            "mdev": timing[3],
            "total": total,
            "loss": loss,
        }
    except Exception as e:
        return None


def ping_ip(ip_addr, ip_host_dict):
    """Ping an IP address after a small random delay to avoid rate limiting or saturation of ICMP traffic,
    also reverse DNS lookup on the IP address & store results in a dictionary"""
    time.sleep(random.random() * 1.2)
    if ping(ip_addr) != None:
        try:
            reverse_dns = socket.gethostbyaddr(ip_addr)
        except socket.herror:
            ip_host_dict[ip_addr] = ""
        else:
            ip_host_dict[ip_addr] = reverse_dns[0]


def ping_sweep(target_device, community):
    """Pull interface IP addressing via SNMP & ping connected networks"""
    command_generator = cmdgen.CommandGenerator()
    authentication = cmdgen.CommunityData(community)
    try:
        target = cmdgen.UdpTransportTarget((target_device, 161))
    except pysnmp.error.PySnmpError as e:
        print(f"Error: {target_device} - {e}")
        return

    # Send a GETBULK request for the OIDs we want
    snmp_engine_error, error_status, error_index, variables = command_generator.bulkCmd(
        authentication,
        target,
        0,
        25,
        # Interface index <-> IP address
        "1.3.6.1.2.1.4.20.1.2",
        # Interface IP <-> subnet mask
        "1.3.6.1.2.1.4.20.1.3",
        # Interface index <-> name (MIB extensions)
        "1.3.6.1.2.1.31.1.1.1.1",
        lookupMib=False,
        lexicographicMode=False,
    )

    if snmp_engine_error:
        print(f"Error: {target_device} - {snmp_engine_error}")
        return

    if error_status:
        print(
            f"Error: {target_device} - {error_status.prettyPrint()} at {error_index and variables[int(error_index) - 1][0] or '?'}"
        )
        return

    # Extract the data we need from the response
    if_index_to_name = {}
    if_index_to_address = {}
    if_ip_to_subnet_mask = {}
    longest = 0

    for r in variables:
        for name, val in r:
            oid = name if isinstance(name, str) else name.prettyPrint()
            value = val.prettyPrint()
            if (
                oid == "No more variables left in this MIB View"
                or value == "No more variables left in this MIB View"
            ):
                continue

            # 1-based index <-> interface name
            if oid[0:23] == "1.3.6.1.2.1.31.1.1.1.1.":
                if_index_to_name[int(oid[oid.rindex(".") + 1 :])] = value
                longest = max(longest, len(value))
            # 1-based index <-> interface ip address
            if oid[0:20] == "1.3.6.1.2.1.4.20.1.2":
                if_index_to_address[int(value)] = extract_ip_from_oid(oid)
            # IP address <-> subnet mask
            if oid[0:20] == "1.3.6.1.2.1.4.20.1.3":
                if_ip_to_subnet_mask[extract_ip_from_oid(oid)] = value

    if len(if_index_to_name) == 0:
        print(
            f"Error: {target_device} could not get the interface table, dumping raw data instead:"
        )
        print(if_index_to_address)
        print(if_ip_to_subnet_mask)
        return

    ip_addr_list = []
    for i in if_index_to_name:
        # Skip interfaces without an IP address
        if i not in if_index_to_address:
            continue

        ip = if_index_to_address[i]

        if ip in if_ip_to_subnet_mask:
            mask = "/" + str(mask_to_prefix(if_ip_to_subnet_mask[ip]))
        else:
            mask = " (unknown subnet mask)"

        # Multi-threaded ping of valid host IP addresses for the network, ignoring loopback 127.0.0.0/8 addresses
        ip_and_host_dict = {}
        if ip[: int(ip.index("."))] != "127":
            workers = []
            # Determine list of IP addresses, including handling /31 subnet masks
            ip_network = ipaddress.IPv4Network(ip + mask, strict=False)
            if mask == "/31":
                ip_list = [ip_network.network_address, ip_network.broadcast_address]
            else:
                ip_list = list(ip_network.hosts())

            for host_ip in ip_list:
                worker = threading.Thread(
                    target=ping_ip, args=(host_ip.exploded, ip_and_host_dict)
                )
                workers.append(worker)
                worker.start()
            for worker in workers:
                worker.join()

            # Store sorted list of IP addresses & hostnames that responded
            for ip_addr in sorted(
                ip_and_host_dict.keys(),
                key=lambda ip_addr: (
                    int(ip_addr.split(".")[0]),
                    int(ip_addr.split(".")[1]),
                    int(ip_addr.split(".")[2]),
                    int(ip_addr.split(".")[3]),
                ),
            ):
                ip_addr_list.append(f"{ip_addr} {ip_and_host_dict[str(ip_addr)]}")

    return ip_addr_list
