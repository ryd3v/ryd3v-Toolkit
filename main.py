#  Title: ryd3v Toolkit
#  Description: Cybersecurity enumeration Tool
#  Author: Ryan Collins(ryd3v.com)
#  Date: 2024
#  TCP Port Scanning.
#  UDP Port Scanning.
#  Scan with Nikto.
#  Netdiscover (must be root!)
#
# Copyright 2024 Ryan Collins
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pexpect
from tqdm import tqdm
import os
import sys
import time
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import threading
import itertools


def check_tool_installed(tool_name):
    try:
        # Use 'which' for UNIX-based systems and 'where' for Windows.
        command = 'which' if os.name != 'nt' else 'where'
        subprocess.check_output([command, tool_name], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        print(f"Error: {tool_name} is not installed. Please install it and run the tool again.")
        sys.exit(1)


def preflight_checks():
    tools = ["nikto", "netdiscover", "dirb", "nmap"]
    for tool in tools:
        check_tool_installed(tool)


def show_progress_indicator(running):
    symbols = itertools.cycle('-\\|/')
    while running.is_set():
        sys.stdout.write(next(symbols))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')


def scan_tcp_ports(ip, start_port, end_port=None, output_file=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_tcp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning TCP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    if output_file:
        with open(output_file, 'w') as f:
            f.write("Open TCP ports on {}: {}\n".format(ip, open_ports))
    else:
        # Only print a summary if no output file is provided
        print("Scan complete. Found {} open TCP ports on {}.".format(len(open_ports), ip))

    return open_ports


def scan_udp_ports(ip, start_port, end_port=None, output_file=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_udp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning UDP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    if output_file:
        with open(output_file, 'w') as f:
            f.write("Open UDP ports on {}: {}\n".format(ip, open_ports))
    else:
        # Only print a summary if no output file is provided
        print("Scan complete. Found {} open UDP ports on {}.".format(len(open_ports), ip))

    return open_ports


def scan_tcp_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def scan_udp_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)  # Set a timeout for the UDP socket
            sock.sendto(b'X', (ip, port))
            data, addr = sock.recvfrom(1024)
            print(f"UDP port {port} open on {ip}")
            return True
    except (socket.timeout, OSError):
        return False


# Nikto
def scan_with_nikto(url):
    output_file = 'nikto.txt'
    try:
        command = f"nikto -host {url} -output='{output_file}'"

        # Start progress indicator
        running = threading.Event()
        running.set()
        progress_thread = threading.Thread(target=show_progress_indicator, args=(running,))
        progress_thread.start()

        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Stop progress indicator
        running.clear()
        progress_thread.join()

        with open(output_file, 'r') as file:
            nikto_results = file.read()
        return nikto_results
    except subprocess.CalledProcessError as e:
        print(f"Error executing Nikto: {e.output}")
        return None


# Netdiscover
def run_netdiscover(ip_range, output_file=None):
    try:
        # Run the netdiscover command and capture the output
        command = f"sudo netdiscover -r {ip_range}"
        process = pexpect.spawn(command)
        while True:
            try:
                line = process.readline()
            except pexpect.exceptions.TIMEOUT:
                break
            if not line:
                break
            line = line.decode().strip()
            print(line)
            if "Currently scanning: Finished!" in line:
                break
            if output_file:
                with open(output_file, 'w') as f:
                    while True:
                        try:
                            line = process.readline()
                        except pexpect.exceptions.TIMEOUT:
                            break
                        if not line:
                            break
                        line = line.decode().strip()
                        f.write(line + '\n')
                        print(line)
                        if "Currently scanning: Finished!" in line:
                            break
            else:
                while True:
                    try:
                        line = process.readline()
                    except pexpect.exceptions.TIMEOUT:
                        break
                    if not line:
                        break
                    line = line.decode().strip()
                    print(line)
                    if "Currently scanning: Finished!" in line:
                        break
        process.wait()
    except subprocess.CalledProcessError as e:
        print(f"Error executing netdiscover: {e.output}")


# Web Directory Scanning (using dirb)
def run_dirb(url, wordlist, output_file=None):
    try:
        if output_file:
            command = f"dirb {url} {wordlist} -o {output_file} -S"
        else:
            command = f"dirb {url} {wordlist} -o dirb.txt -S"

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
        process.wait()
    except subprocess.CalledProcessError as e:
        print(f"Error executing Dirb: {e.output}")


def scan_target(ip, start_port=1, end_port=65535, output_file=None):
    # Perform TCP and UDP scans
    tcp_scan_results = scan_tcp_ports(ip, start_port, end_port)
    udp_scan_results = scan_udp_ports(ip, start_port, end_port)

    # Combine the results into a single string
    combined_results = f"Open TCP ports on {ip}: {tcp_scan_results}\nOpen UDP ports on {ip}: {udp_scan_results}"

    # Write results to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write(combined_results)

    # Return the combined results
    return combined_results


def run_nmap_scan(ip):
    nmap_results = ""
    try:
        command = f"nmap -Pn -sS -sV -A {ip}"

        # Start progress indicator
        running = threading.Event()
        running.set()
        progress_thread = threading.Thread(target=show_progress_indicator, args=(running,))
        progress_thread.start()

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
            nmap_results += line
        process.wait()

        # Stop progress indicator
        running.clear()
        progress_thread.join()

        # Optionally, save to file as well
        with open('scan.txt', 'w') as file:
            file.write(nmap_results)

        return nmap_results
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap: {e.output}")
        return None


def generate_pdf_report(file_name, scan_data, target, scan_type):
    c = canvas.Canvas(file_name, pagesize=letter)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Header
    c.drawString(50, 800, "Ryd3v Toolkit Scan Report")
    c.drawString(50, 785, f"Report Generated: {timestamp}")
    c.drawString(50, 770, f"Target: {target}")
    c.drawString(50, 755, f"Scan Type: {scan_type}")

    # Body
    y = 730
    for line in scan_data.split('\n'):
        c.drawString(50, y, line)
        y -= 15
        if y < 50:
            c.showPage()
            y = 750
    c.save()


def main():
    tcp_scan_results = ""
    udp_scan_results = ""
    nikto_results = ""
    nmap_results = ""
    full_scan_results = ""

    while True:
        print("Welcome to ryd3v Toolkit!")
        print("Select a task:")
        print("1. TCP Port Scanning")
        print("2. UDP Port Scanning")
        print("3. Scan a URL with Nikto")
        print("4. Run netdiscover (must be root!)")
        print("5. Web Directory Scanning (dirb)")
        print("6. Full TCP and UDP Port Scanning")
        print("7. Run nmap scan")
        print("8. Report Generation")
        print("9. Exit")
        choice = int(input())

        if choice == 1:
            ip = input("Enter the IP address to scan: ")
            scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")

            open_ports = []  # Initialize open_ports

            if scan_option.lower() == 'all':
                open_ports = scan_tcp_ports(ip, start_port=1, end_port=65535)
            elif scan_option.lower() == 'range':
                start_port = int(input("Enter the starting port: "))
                end_port = int(input("Enter the ending port: "))
                open_ports = scan_tcp_ports(ip, start_port=start_port, end_port=end_port)
            else:
                print("Invalid option. Please choose 'all' or 'range'.")
                continue

            tcp_scan_results = "Open TCP ports on {}: {}".format(ip, open_ports)
            print(tcp_scan_results)

            # Write to file if the user has specified one
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(tcp_scan_results)

        elif choice == 2:
            ip = input("Enter the IP address to scan: ")
            scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")
            open_ports = []  # Initialize open_ports

            if scan_option.lower() == 'all':
                open_ports = scan_udp_ports(ip, start_port=1, end_port=65535, output_file=output_file)
            elif scan_option.lower() == 'range':
                start_port = int(input("Enter the starting port: "))
                end_port = int(input("Enter the ending port: "))
                open_ports = scan_udp_ports(ip, start_port=start_port, end_port=end_port, output_file=output_file)
            else:
                print("Invalid option. Please choose 'all' or 'range'.")
                continue

            udp_scan_results = "Open UDP ports on {}: {}".format(ip, open_ports)
            print(udp_scan_results)

        elif choice == 3:
            url = input("Enter the URL you want to scan with Nikto: ")
            nikto_results = scan_with_nikto(url)

        elif choice == 4:
            ip_range = input("Enter the IP address range (e.g., 192.168.2.1/24). "
                             "Press Ctrl+C to cancel the scan: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")
            run_netdiscover(ip_range, output_file=output_file)

        elif choice == 5:
            url = input("Enter the URL you want to scan with Dirb: ")
            wordlist = input("Enter the path to the wordlist file: ")
            output_file = "dirb_results.txt"
            run_dirb(url, wordlist, output_file=output_file)

        elif choice == 6:
            ip = input("Enter the IP address to scan: ")
            full_scan_results = scan_target(ip)
            print(full_scan_results)

        elif choice == 7:
            ip = input("Enter the IP address to scan with nmap: ")
            nmap_results = run_nmap_scan(ip)
            print("Nmap scan results saved to scan.txt.")

        elif choice == 8:
            if tcp_scan_results or udp_scan_results or nikto_results or nmap_results or full_scan_results:
                combined_results = f"{tcp_scan_results}\n{udp_scan_results}\n{nikto_results}\n{nmap_results}\n{full_scan_results}"
                report_file = "Ryd3v_Toolkit_Report.pdf"
                target = ip  # or another way to specify the target
                scan_type = "Comprehensive Scan"
                generate_pdf_report(report_file, combined_results, target, scan_type)
                print(f"Report generated and saved as {report_file}")
            else:
                print("No scan results to report.")

        elif choice == 9:
            print("Exiting ryd3v Toolkit. Goodbye!")
            break
        else:
            print("Invalid option. Please choose a valid task.")


if __name__ == "__main__":
    preflight_checks()
    main()
