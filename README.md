# Automated Pre & Post Checks

Copyright (c) 2022 - 2024, Chris Perkins

Connects via SSH to a specified list of network devices, automatically detects the platform & runs platform specific commands. Features additional role specific checks based on partial hostnames, optional ping sweep (pulls interface IP addresses via SNMP) & VRF aware BGP peer routes check. HTML post checks report with command output diffs is emailed out to specified email address as a zip file attachment.
Each SSH session to a device is handled in a separate thread, for reduced execution times when running against multiple devices.

Contains modified version of diff2HtmlCompare, (c) 2016 Alex Goodman, https://github.com/wagoodman/diff2HtmlCompare & used under the MIT licence.

Contains modified version of NetMiko's ssh_autodetect.py, (c) 2016 - 2023 Kirk Byers et al. https://github.com/ktbyers/netmiko & used under the MIT licence.

Uses code from get_routing_table.py v2.0, (c) Jarmo Pietiläinen 2013 - 2014, http://z0b.kapsi.fi/networking.php & used under the zlib/libpng licence.

IP address sorting courtesy of https://www.python4networkengineers.com/posts/how_to_sort_ip_addresses_with_python/

HTML top button courtesy of Heather Tovey: https://heathertovey.com/blog/floating-back-to-top-button/


Caveats:
1. IPv4 only for the ping sweep & BGP peer routes check.
2. BGP peer check supports IOS, IOS XE, NX-OS, EOS & JunOs platforms.
3. SMTP server authentication code path isn't exposed currently.
4. SNMP v3 isn't supported currently.


Version History:
* v1.3.1 - Reworked to use PySNNP v7.1+.
* v1.3 - SNMP ping sweep now using "1.3.6.1.2.1.4.32" & "1.3.6.1.2.1.4.34" OIDs to support more vendors, IPv6 & interfaces with multiple IP addresses.
* v1.2.1 - Added forcing pre-check rerun.
* v1.2 - Bug fix SNMP ping sweep.
* v1.1 - Updated NetMiko Exceptions, code tidying, switched to base64 password & added NetMiko auto-detection for Aruba CX devices.
* v1.0 - Added VRF aware BGP peer advertised & received routes check. Made checkouts executed in a separate thread per device.
* v0.4 - Improvements to settings & checkouts validation, added optional proxy server support.
* v0.3 - Integrated diff2HtmlCompare for prettier output & now storing outputs in a zip file.
* v0.2 - Added role specific checkouts.
* v0.1 - Initial development release.

## Pre-Requisites
* Python 3.9+
* NetMiko 4.1+
* PySNMP 7.1+
* Runs on Linux

## Installation
Copy the entire project into a directory on a Linux server that has both SSH & SNMP access to the network devices that checkouts will be performed on.

Install the required Python packages via *pip install -r requirements.txt*

## Configuration
*pre-post_checker.py* has a global variable "BASE_PATH" that should be updated to reflect the path where the tool is located. By default it is set to "./".

*settings.json* contains multiple parameters that should be updated to match your environment:

username - username of the account used to connect to network devices.

sender_email - email address checkout reports are sent from.

receiver_email - email address checkout reports are sent to.

temp_path - path where temporary files should be stored.

smtp_server - FQDN of SMTP server to use for sending emails.

smtp_port - port number used by the SMTP server.

proxy_server - if specified, FQDN of proxy server to use to reach the SMTP server.

proxy_type - type of proxy server, 1 = SOCKS4, 2 = SOCKS5 & 3 = HTTP.

proxy_port - port number used by the proxy server.

*checkout_definitions.json* contains a list of supported platforms, commands to run against each platform & role specific commands. The platform names are the NetMiko device type, see https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md for a complete list.

Within each platform there is the SNMP community to use & the list of commands to run for each role. The "common" list of commands will always be run, any other list of commands will be run if the key is found in the hostname of the device that checks are being performed against. The assumption is that the device naming scheme has an indication of the device's role in the hostname, e.g. "user" for a switch connected to end user devices or "serv" for a switch connected to servers.

There are two special commands - "CHECK_BGP" & "PING_SWEEP", these must be in upper case. CHECK_BGP will call the VRF aware BGP peer routes checks. PING_SWEEP will poll a device's interface IP addresses & subnet masks via SNMP, then run a ping sweep against these networks.

Example checkout definition:
```
{
    "arista_eos": {
        "community": "public",
        "commands": {
            "common": [
                "show clock",
                "show vlan brief",
                "show ip arp vrf all",
                "show interface status",
                "show ip interface brief",
                "show interface counter error",
                "show interface counter discard",
                "show lldp neighbor",
                "show ip ospf neighbor",
                "show ip bgp summary vrf all",
                "CHECK_BGP",
                "show ip route vrf all summary",
                "show ip route vrf all",
                "show system environment all",
                "show version",
                "show inventory",
                "show running-config"
            ],
            "serv": [
                "show mac address-table",
                "show ip bgp vrf all",
                "show mlag detail",
                "PING_SWEEP"
            ]
        }
    }
}
```

## Usage
Command line parameters, for those with spaces enclose the parameter in "":

* change control ID - identifier for the change control the checkouts are for, must form a valid Linux filename
* password - base64 encoded password for the account specified in settings.json
* space delimited list of hostnames - must be resolvable via DNS or an IPv4 address

For example:
*python pre-post_checker.py 4321 Password123 device1.somewhere.com device2.somewhere.com device3.somewehere.com*

The first run of the tool will create a directory in the temporary files path, named after the change control ID. The output of the pre-checks will be stored as text files in this directory.

If you accidentally specified an incorrect list of hostnames & the pre-checks have been run, you can force the pre-checks to be rerun from scratch by adding --force-precheck to the list of hostnames.

The second run of the tool will store the outputs of the post-checks in this directory, run a diff against the pre & post checks, generate an HTML report & send an email with it attached as a zip file.
