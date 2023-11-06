#!/usr/bin/env python3

"""
Copyright (c) 2022 - 2023, Chris Perkins
Licence: BSD 3-Clause

Automated pre & post checks with platform specific code paths, additional role checks based on partial
hostnames & optional ping sweep and/or VRF aware BGP peer routes check.
Post check results are emailed to specified email address as a zip file attachment.

v1.2 - Bug fix SNMP ping sweep.
v1.1 - Updated NetMiko Exceptions, code tidying, switched to base64 password & added NetMiko auto-detection for Aruba CX devices.
v1.0 - Added VRF aware BGP peer advertised & received routes check. Made checkouts executed in a
separate thread per device.
v0.4 - Improvements to settings & checkouts validation, added optional proxy server support.
v0.3 - Integrated diff2HtmlCompare for prettier output & now storing outputs in a zip file.
v0.2 - Added role specific checkouts.
v0.1 - Initial development release.
"""

import sys
import re
import socket
import os
import json
import smtplib
import socks
import ssl
import base64
import SNMP_ping_sweep
import diff2HtmlCompare
import argparse
import shutil
import threading
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException

# from netmiko.ssh_autodetect import SSHDetect
from ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
from jinja2 import Template, Environment, FileSystemLoader, StrictUndefined
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

BASE_PATH = "./"  # Directory where the tool is located


def guess_device_type(remote_device):
    """Auto-detect device type."""
    try:
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
    except (NetMikoAuthenticationException):
        print(
            f"Error: Failed to execute CLI on {remote_device['host']} due to incorrect credentials."
        )
        return None
    except (NetMikoTimeoutException, SSHException):
        print(
            f"Error: Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled."
        )
        return None
    except ValueError:
        print(
            f"Error: Unsupported platform {remote_device['host']}, {remote_device['device_type']}."
        )
        return None
    else:
        return best_match


def perform_checkouts(
    pre_check, dir_path, settings, checkouts, target_device, password, checkouts_output
):
    """SSH to a device, run the commands for that platform & output the results."""
    checkout_messages = ""
    try:
        # Auto-detect device type & establish correct SSH connection
        best_match = guess_device_type(
            {
                "device_type": "autodetect",
                "host": target_device,
                "username": settings["username"],
                "password": password,
                "secret": password,
                "read_timeout_override": 60,
                "fast_cli": False,
            }
        )
        if best_match is None:
            checkout_messages += f"Error: Unknown platform for {target_device}.\n"
            checkouts_output.append(checkout_messages)
            return

        checkout_messages += (
            f"\nConnecting to device: {target_device}, type: {best_match}.\n"
        )
        device = ConnectHandler(
            device_type=best_match,
            host=target_device,
            username=settings["username"],
            password=password,
            secret=password,
            read_timeout_override=100,
            fast_cli=False,
            global_cmd_verify=False,
        )
    except (NetMikoAuthenticationException):
        checkout_messages += f"Error: Failed to execute CLI on {target_device} due to incorrect credentials.\n"
        checkouts_output.append(checkout_messages)
        return
    except (NetMikoTimeoutException, SSHException):
        checkout_messages += f"Error: Failed to execute CLI on {target_device} due to timeout or SSH not enabled.\n"
        checkouts_output.append(checkout_messages)
        return
    except ValueError:
        checkout_messages += (
            f"Error: Unsupported platform {target_device}, {best_match}.\n"
        )
        checkouts_output.append(checkout_messages)
        return

    if checkouts.get(best_match, None) is None:
        checkout_messages += f"Error: Platform {best_match} has no checkouts defined.\n"
        checkouts_output.append(checkout_messages)
        return

    device.enable()
    # Generate list of commands to run
    checkout_names = ""
    if not checkouts[best_match]["commands"].get("common", None):
        checkout_messages += (
            f"Error: Platform {best_match} has no common checkouts defined.\n"
        )
        command_list = []
    else:
        checkout_names += "common"
        command_list = checkouts[best_match]["commands"]["common"].copy()
    for key, value in checkouts[best_match]["commands"].items():
        if key.lower() in target_device.lower():
            command_list.extend(value)
            checkout_names += f" {key.lower()}"

    # Run each command in the checkouts definition & store the output in a file named after the
    # hostname, command & whether it's pre or post check, to allow diff to be run later
    checkout_messages += f"Running checkouts: {checkout_names}\n"
    for command in command_list:
        # Special cases for BGP peer check & SNMP ping sweep
        if command == "CHECK_BGP":
            checkout_messages += check_bgp_peers(
                pre_check, dir_path, best_match, target_device, device
            )
        elif command == "PING_SWEEP":
            ip_addr_list = SNMP_ping_sweep.ping_sweep(
                target_device, checkouts[best_match]["community"]
            )
            cli_output = "Ping Sweep\n"
            if ip_addr_list:
                cli_output += "\n".join([f"{ip_addr}" for ip_addr in ip_addr_list])
            file_path = Path(
                dir_path
                / f"{target_device}_ping-sweep{'_pre' if pre_check else '_post'}"
            )
            try:
                with open(file_path, "w") as f:
                    f.write(cli_output)
            except OSError:
                checkout_messages += f"Error: Unable to write file {file_path}.\n"
        else:
            cli_output = f"{command}\n"
            cli_output += device.send_command(command)
            file_path = Path(
                dir_path
                / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
            )
            try:
                with open(file_path, "w") as f:
                    f.write(cli_output)
            except OSError:
                checkout_messages += f"Error: Unable to write file {file_path}.\n"

    device.disconnect()
    checkouts_output.append(checkout_messages)


def check_bgp_peers(pre_check, dir_path, best_match, target_device, device):
    """VRF aware checkout for BGP neighbour advertised & received routes"""
    checkout_messages = ""
    if best_match == "arista_eos":
        cli_output = device.send_command("show vrf")
        VRF_names = []
        # Find column heading line & then parse VRF names in lines below
        cntr = 0
        for line in cli_output.splitlines():
            cntr += 1
            if "-------------" in line:
                break
        for line in cli_output.splitlines()[cntr:]:
            columns = line.split()
            if len(columns) >= 5:
                VRF_names.append(columns[0])

        for VRF in VRF_names:
            cli_output = device.send_command(f"show ip bgp summary vrf {VRF}")
            # Find column heading line & then parse BGP peers in lines below
            cntr = 0
            for line in cli_output.splitlines():
                cntr += 1
                if "Description" in line:
                    break
            for line in cli_output.splitlines()[cntr:]:
                ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
                if ip_addr:
                    command = f"show ip bgp neighbor {ip_addr.group(1)} advertised-routes vrf {VRF}"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )
                    command = f"show ip bgp neighbor {ip_addr.group(1)} received-routes vrf {VRF}"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )

    elif best_match == "cisco_ios" or best_match == "cisco_xe":
        cli_output = device.send_command("show vrf")
        VRF_names = []
        # Find column heading line & then parse VRF names in lines below
        cntr = 0
        for line in cli_output.splitlines():
            cntr += 1
            if "Name" in line:
                break
        for line in cli_output.splitlines()[cntr:]:
            columns = line.split()
            if len(columns) >= 4:
                VRF_names.append(columns[0])

        # IOS syntax for the default VRF is different from other VRFs
        cli_output = device.send_command(f"show ip bgp summary")
        # Find column heading line & then parse BGP peers in lines below
        cntr = 0
        for line in cli_output.splitlines():
            cntr += 1
            if "Neighbor" in line:
                break
        for line in cli_output.splitlines()[cntr:]:
            ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
            if ip_addr:
                command = f"show ip bgp neighbor {ip_addr.group(1)} advertised-routes"
                cli_output2 = f"{command}\n"
                cli_output2 += device.send_command(command)
                file_path = Path(
                    dir_path
                    / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                )
                try:
                    with open(file_path, "w") as f:
                        f.write(cli_output2)
                except OSError:
                    checkout_messages += f"Error: Unable to write file {file_path}.\n"
                command = f"show ip bgp neighbor {ip_addr.group(1)} received-routes"
                cli_output2 = f"{command}\n"
                cli_output2 += device.send_command(command)
                file_path = Path(
                    dir_path
                    / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                )
                try:
                    with open(file_path, "w") as f:
                        f.write(cli_output2)
                except OSError:
                    checkout_messages += f"Error: Unable to write file {file_path}.\n"

        for VRF in VRF_names:
            cli_output = device.send_command(f"show ip bgp vpnv4 vrf {VRF} summary")
            # Find column heading line & then parse BGP peers in lines below
            cntr = 0
            for line in cli_output.splitlines():
                cntr += 1
                if "Neighbor" in line:
                    break
            for line in cli_output.splitlines()[cntr:]:
                ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
                if ip_addr:
                    command = f"show ip bgp vpnv4 vrf {VRF} neighbor {ip_addr.group(1)} advertised-routes"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )
                    command = f"show ip bgp vpnv4 vrf {VRF} neighbor {ip_addr.group(1)} received-routes"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )

    elif best_match == "cisco_nxos":
        cli_output = device.send_command("show vrf")
        VRF_names = []
        # Find column heading line & then parse VRF names in lines below
        cntr = 0
        for line in cli_output.splitlines():
            cntr += 1
            if "VRF-Name" in line:
                break
        for line in cli_output.splitlines()[cntr:]:
            columns = line.split()
            if len(columns) >= 4:
                VRF_names.append(columns[0])

        for VRF in VRF_names:
            cli_output = device.send_command(f"show ip bgp summary vrf {VRF}")
            # Find column heading line & then parse BGP peers in lines below
            cntr = 0
            for line in cli_output.splitlines():
                cntr += 1
                if "Neighbor" in line:
                    break
            for line in cli_output.splitlines()[cntr:]:
                ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
                if ip_addr:
                    command = f"show ip bgp neighbor {ip_addr.group(1)} advertised-routes vrf {VRF}"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )
                    command = f"show ip bgp neighbor {ip_addr.group(1)} received-routes vrf {VRF}"
                    cli_output2 = f"{command}\n"
                    cli_output2 += device.send_command(command)
                    file_path = Path(
                        dir_path
                        / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                    )
                    try:
                        with open(file_path, "w") as f:
                            f.write(cli_output2)
                    except OSError:
                        checkout_messages += (
                            f"Error: Unable to write file {file_path}.\n"
                        )

    elif best_match == "juniper" or best_match == "juniper_junos":
        cli_output = device.send_command(f"show bgp summary")
        # Find column heading line & then parse BGP peers in lines below
        cntr = 0
        for line in cli_output.splitlines():
            cntr += 1
            if "Peer " in line:
                break
        for line in cli_output.splitlines()[cntr:]:
            ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
            if ip_addr:
                command = f"show route advertising-protocol bgp {ip_addr.group(1)}"
                cli_output2 = f"{command}\n"
                cli_output2 += device.send_command(command)
                file_path = Path(
                    dir_path
                    / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                )
                try:
                    with open(file_path, "w") as f:
                        f.write(cli_output2)
                except OSError:
                    checkout_messages += f"Error: Unable to write file {file_path}.\n"
                command = f"show route receive-protocol bgp {ip_addr.group(1)}"
                cli_output2 = f"{command}\n"
                cli_output2 += device.send_command(command)
                file_path = Path(
                    dir_path
                    / f"{target_device}_{command.replace(' ', '-').replace('|', '-')}{'_pre' if pre_check else '_post'}"
                )
                try:
                    with open(file_path, "w") as f:
                        f.write(cli_output2)
                except OSError:
                    checkout_messages += f"Error: Unable to write file {file_path}.\n"

    return checkout_messages


def send_report_email(cc_id, file_path, settings):
    """Email checkout HTML report as an attachment."""
    # Create a multipart message and set headers
    subject = f"Checkout Report for Change Control #{cc_id}"
    body = f"See attachment {file_path.name} for details."
    message = MIMEMultipart()
    message["From"] = settings["sender_email"]
    message["To"] = settings["receiver_email"]
    message["Subject"] = subject
    # message["Bcc"] = settings["receiver_email"]

    # Configure proxy settings, if required
    if settings["proxy_server"]:
        socks.setdefaultproxy(
            settings["proxy_type"], settings["proxy_server"], settings["proxy_port"]
        )
        socks.wrapmodule(smtplib)

    # Add body to email
    message.attach(MIMEText(body, "plain"))
    # Open attachment file in binary mode
    with open(file_path, "rb") as attachment:
        # Add file as application/octet-stream, email client can usually download this automatically as attachment
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
    # Encode file as base64 to send by email
    encoders.encode_base64(part)
    # Add header as key/value pair to attachment part
    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {file_path.name}",
    )
    # Add attachment to message and convert message to string
    message.attach(part)
    text = message.as_string()

    # Log in to server using secure context and send email
    # context = ssl.create_default_context()
    # context = ssl.SSLContext() # Kludge to disable certificate verification
    try:
        server = smtplib.SMTP(settings["smtp_server"], settings["smtp_port"])
        server.ehlo()
        # server.starttls(context=context) # Secure the connection
        # server.ehlo()
        # server.login(settings["sender_email"], email_password)
        server.sendmail
        server.sendmail(settings["sender_email"], settings["receiver_email"], text)
        server.quit()
    except Exception as e:
        # Print any error messages to stdout
        print(f"Error: {e}.")


def generate_report(cc_id, dir_path, device_list, settings):
    """Load checkout outputs, run diffs & generate HTML report."""
    diff_output_dict = {}
    # Iterate through files containing outputs for each device & create dictionary of details
    for target_device in device_list:
        diff_output_dict[target_device] = {}
        for file_path1 in dir_path.glob(f"{target_device}_*_pre"):
            if not file_path1.is_file():
                continue
            # This code is ugly :(
            try:
                with open(file_path1) as f:
                    precheck_text = f.readlines()
            except FileNotFoundError:
                print(f"Error: Unable to open {file_path1}.")
                continue
            try:
                file_path2 = Path(str(file_path1).replace("_pre", "_post"))
                with open(file_path2) as f:
                    postcheck_text = f.readlines()
            except FileNotFoundError:
                print(f"Error: Unable to open {file_path2}.")
                continue

            # Extract the name of the command, run diff & add outputs to dictionary
            command = precheck_text[0]
            codeDiff = diff2HtmlCompare.CodeDiff(
                str(file_path1), str(file_path2), name=str(file_path2)
            )
            codeDiff.format(
                argparse.Namespace(print_width=False, syntax_css="vs", verbose=False)
            )
            diff_output_dict[target_device][command] = codeDiff.htmlContents

    # Generate HTML report using Jinja2 template
    file_loader = FileSystemLoader(BASE_PATH)
    env = Environment(loader=file_loader, undefined=StrictUndefined)
    template = env.get_template("checkout_report.j2")
    file_path = Path(dir_path / f"CC_{cc_id}.html")
    try:
        with open(file_path, "w") as f:
            f.write(template.render(cc_id=cc_id, diff_output_dict=diff_output_dict))
    except OSError:
        print(f"Error: Unable to write file {file_path}.")
        sys.exit(1)
    try:
        shutil.copytree(Path(BASE_PATH) / "deps", dir_path / "deps", dirs_exist_ok=True)
    except OSError:
        print(f"Error: Unable to copy files to {dir_path / 'deps'}.")

    # Create a zip file from the checkouts files
    file_path = Path(dir_path / f"CC_{cc_id}.zip")
    try:
        with ZipFile(str(file_path), "w", ZIP_DEFLATED) as zf:
            for directory in dir_path.glob("**"):
                for file in directory.iterdir():
                    if not file.is_file():
                        continue
                    # Don't zip the zip file!
                    if file == file_path:
                        continue
                    # Adjust the arcname to start after the change ID
                    zip_path = Path(*file.parts[file.parts.index(cc_id) + 1 :])
                    zf.write(str(file), str(zip_path))
    except (ValueError, OSError):
        print(f"Error: Unable to create zip file {file_path}.")
    else:
        # Email the report as an attachment
        print(f"\nEmailing checkouts report to {settings['receiver_email']}.")
        send_report_email(cc_id, file_path, settings)


def main():
    """Parse command line arguments, load checkout definitions & determine if pre or post checks."""
    if len(sys.argv) <= 3:
        print(
            f"Usage: {sys.argv[0]} [change control ID] [base64 encoded password] [space delimited list of hostnames]"
        )
        sys.exit(1)

    # Sanity check parameters
    device_list = []
    for i in sys.argv[3:]:
        hostname = re.search(r"^[\w\-\.]+$", i)
        if not hostname:
            print(f"Error: Invalid hostname {i}.")
            sys.exit(1)
        else:
            hostname = hostname.group(0)
            try:
                dns_lookup = socket.gethostbyname(hostname)
            except socket.gaierror:
                print(f"Error: Unable to resolve {hostname}.")
                sys.exit(1)
            else:
                device_list.append(hostname)

    # Load JSON settings
    try:
        file_path = Path(BASE_PATH) / "settings.json"
        with open(file_path) as f:
            settings = json.load(f)
    except json.JSONDecodeError:
        print("Error: Unable to parse settings.json.")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: Unable to open settings.json.")
        sys.exit(1)
    # Sanity checks for settings
    if not settings.get("username", None):
        print(f"Error: Username must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("sender_email", None):
        print(f"Error: Sender email address must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("receiver_email", None):
        print(f"Error: Receiver email address must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("temp_path", None):
        print(f"Error: Temporary storage directory must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("smtp_server", None):
        print(f"Error: SMTP server must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("smtp_port", None):
        print(f"Error: SMTP server port must be specified in settings.json.")
        sys.exit(1)
    if settings.get("proxy_server", None) is None:
        print(f"Error: Proxy server must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("proxy_type", None):
        print(f"Error: Proxy server type must be specified in settings.json.")
        sys.exit(1)
    if not settings.get("proxy_port", None):
        print(f"Error: Proxy server port must be specified in settings.json.")
        sys.exit(1)

    # Load JSON checkouts definitions
    try:
        file_path = Path(BASE_PATH) / "checkout_definitions.json"
        with open(file_path) as f:
            checkouts = json.load(f)
    except json.JSONDecodeError:
        print("Error: Unable to parse checkout_definitions.json.")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: Unable to open checkout_definitions.json.")
        sys.exit(1)
    # Sanity checks for checkouts
    for device_type in checkouts.keys():
        if checkouts[device_type].get("community", None) is None:
            print(
                f"Error: {device_type} SNMP community must be specified in checkout_definitions.json."
            )
            sys.exit(1)
        if not checkouts[device_type].get("commands", None):
            print(
                f"Error: {device_type} checkout commands must be specified in checkout_definitions.json."
            )
            sys.exit(1)

    # Does the directory for storing checkouts exist? If not create it
    dir_path = Path(settings["temp_path"]) / sys.argv[1]
    if os.path.exists(dir_path):
        pre_check = False
    else:
        os.mkdir(dir_path)
        pre_check = True

    # Run checkouts against each device in a separate thread
    workers = []
    checkouts_output = []
    for target_device in device_list:
        worker = threading.Thread(
            target=perform_checkouts,
            args=(
                pre_check,
                dir_path,
                settings,
                checkouts,
                target_device,
                base64.b64decode(sys.argv[2]).decode("utf-8"),
                checkouts_output,
            ),
        )
        workers.append(worker)
        worker.start()
        for worker in workers:
            worker.join()

    # Display messages from checkouts
    for message in checkouts_output:
        print(message)

    if pre_check:
        print("\nPre-checks completed.")
        # Add outputing list of pre-checks taken
        sys.exit(0)
    else:
        print("\nGenerating checkouts report.")
        generate_report(sys.argv[1], dir_path, device_list, settings)
        sys.exit(0)


if __name__ == "__main__":
    main()
