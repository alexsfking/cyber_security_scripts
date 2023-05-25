#!/usr/bin/env/python
import nmap
import os
import sys
import time
import select

'''
Shebang:
#!/usr/bin/env/python

    This line is called a shebang and specifies the interpreter to be used when
    executing the script. In this case, it indicates that the script should be run
    using the Python interpreter.

Import Statements:
import nmap
import os
import sys
import time
import select

    These statements import the necessary libraries/modules for the script. The nmap
    library is used for network scanning, os and sys for system-related operations,
    and time and select for timing and input handling, respectively.

Class Definition: Scanner

    This class encapsulates the functionality of the web server scanner. It contains
    methods for initializing the scanner, scanning for devices in a given IP range,
    enumerating devices for web servers, extracting script data, and outputting
    results to file or stdout.

Scanner Initialization: __init__ method

    This method is called when creating a new instance of the Scanner class. It
    initializes the available_hosts attribute as an empty set and attempts to create
    an instance of nmap.PortScanner() for network scanning. If an error occurs
    during the creation of the PortScanner object, an error message is printed, and
    the script exits.

Scanning for Devices: scan_for_devices method

    This method performs a network scan on the given target_ip_range using the nmap
    library. The -sn argument specifies a "ping scan" mode, which checks if the
    hosts are up without performing port scanning. The scan results are stored in
    the scan_results variable.

Enumerating Devices: enumerate_devices method

    This method iterates over the set of available_hosts obtained from the previous
    scan. It performs additional operations on each host, such as sending a ping
    request to check if the host is up, scanning for open ports, extracting script
    data related to web servers, and outputting the results.

Outputting Results: output_http_results_to_file and
output_http_results_to_stdout methods

    These methods write the HTTP-related scan results to a file (pwsd_results.txt)
    or print them to the console (stdout).

Extract data: extract_script_data method

    The extract_script_data method is responsible for extracting specific script
    data related to web servers from the scan results. It takes the host IP address
    and port number as parameters.

    The method first retrieves the script data from the scan results for the
    specified host and port. If there is script data available, it extracts specific
    attributes such as http-headers, http-title, http-server-header, http-methods,
    and http-enum using the get method.

    Finally, the extracted script data is returned as a tuple (headers, title,
    server_header, methods, enum). If no script data is found, None is returned.

User Interaction: menu function

    The menu function displays a menu for the user to interact with. It prints the
    menu options and takes user input. It takes an instance of the Scanner class as
    an argument and returns the user's choice as a string.

Input Functions: scan_for_devices and enumerate_devices

    These functions interact with the user to obtain input for scanning IP ranges
    and enumerating devices, respectively. They call the corresponding methods of
    the Scanner class.

Main:

    In the main block, an instance of the Scanner class is created. The file
    "pwsd_results.txt" is cleared.

    The main loop runs until the user chooses the exit option (0). Inside the loop,
    the menu is displayed, and based on the user's choice, the corresponding
    function is called.

    If a keyboard interrupt (Ctrl+C) is detected, a message is printed, and the
    script exits gracefully.

    Finally, a "Goodbye!" message is printed to indicate the end of the script.

'''

class Scanner:
    def __init__(self) -> None:
        self.available_hosts=set()
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print('Nmap not found', sys.exc_info()[0])
            sys.exit(1)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            sys.exit(1)

    def scan_for_devices(self, target_ip_range: str):
        scan_results = self.nm.scan(target_ip_range, arguments='-sn')
        print(scan_results)
        if 'scan' in scan_results:
            for host, data in scan_results['scan'].items():
                if 'status' in data and data['status']['state'] == 'up':
                    if 'reason' in data['status'] and data['status']['reason'] != 'arp-response':
                        self.available_hosts.add(host)


    def enumerate_devices(self):
        #nmap 192.168.159.137 -p 1-65535 -T5 --script=http-title,http-server-header,http-methods,http-headers,http-enum
        for host in self.available_hosts:
            print("Checking: ", host)
            with open('pwsd_results.txt', 'a') as f:
                f.write("Checking: " + str(host) + "\n")
            response = os.system("ping -c 1 " + host + " > /dev/null 2>&1")
            if response == 0:
                start_time:float = time.time()
                try:
                    self.nm.scan(hosts=str(host), arguments='-p 1-65535 -T5 --script=http-title,http-server-header,http-methods,http-headers,http-enum',sudo=True,timeout=160)
                except Exception as e:
                    print(f"An error occurred while scanning host {host}: {str(e)}")
                    continue
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        headers,title,server_header,methods,enum=None,None,None,None,None
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            script_data = self.extract_script_data(host, port)
                            if script_data:
                                headers, title, server_header, methods, enum = script_data
                            if self.nm[host]['tcp'][port]['name'] == 'http' or headers or title or server_header or methods:
                                self.output_http_results_to_stdout(host,port,headers,title,server_header,methods,enum)
                                self.output_http_results_to_file(host,port,headers,title,server_header,methods,enum)

                        elapsed_time = time.time() - start_time
                        if elapsed_time > 300:
                            print("Skipping host", host, "due to timeout.")
                            f.write("Skipping host " + str(host) + " due to timeout." + "\n")
                            break

                        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                            if sys.stdin.readline().strip() == '':
                                print("Skipping host", host, "due to user input.")
                                f.write("Skipping host " + str(host) + " due to user input." + "\n")
                                break
            
        self.available_hosts.clear()
        print("Finished.")
        f.write("Finished.\n")

    def extract_script_data(self, host:str, port:int):
        script = self.nm[host]['tcp'][port].get('script')
        if script:
            headers = script.get('http-headers')
            title = script.get('http-title')
            server_header = script.get('http-server-header')
            methods = script.get('http-methods')
            enum = script.get('http-enum')
            return headers, title, server_header, methods, enum
        return None

    def output_http_results_to_file(self,host:str,port:int,headers,title,server_header,methods,enum):
        with open('pwsd_results.txt', 'a') as f:
            f.write(f"\tPort {port}: {self.nm[host]['tcp'][port]['name']} - {self.nm[host]['tcp'][port]['product']}\n")
            if headers:
                f.write("http-headers: " + str(headers) + "\n")
            if title:
                f.write("http-title: " + str(title) + "\n")
            if server_header:
                f.write("http-server-header: " + str(server_header) + "\n")
            if methods:
                f.write("http-methods: " + str(methods) + "\n")
            if enum:
                f.write("http-enum: " + str(enum) + "\n")

    def output_http_results_to_stdout(self,host:str,port:int,headers,title,server_header,methods,enum):
        print(f"\tPort {port}: {self.nm[host]['tcp'][port]['name']} - {self.nm[host]['tcp'][port]['product']}")
        if(headers):
            print("http-headers: ",headers)
        if(title):
            print("http-title: ",title)
        if(server_header):
            print("http-server-header: ",server_header)
        if(methods):
            print("http-methods: ",methods)
        if(enum):
            print("http-enum: ",enum)


def menu(scanner:Scanner)->str:
    print("╔══════════════════════════════════════════════════╗")
    print("║°τ°o°o°o°°o°°o≈°τ°|   Group 3   |0°o°o°°°°o°τ°≈°°τ║")
    print("╚══════════════════════════════════════════════════╝")
    print("\n***Welcome to our web server discovery script!***\n")
    if(not scanner.available_hosts):
        print("1. Scan IP range for devices.")
    else:
        print("1. Scan MORE IP ranges for devices.")
    if(scanner.available_hosts):
        print("2. Enumerate web servers on detected devices:  ")
        print("\t",', '.join(map(str, scanner.available_hosts)))
    print("0. Exit\n")
    print("Please enter a number to choose an option: ")
    print("")
    choice:str = input().rstrip()
    return choice

def scan_for_devices(scanner:Scanner):
    print("Give an ip range.")
    print("eg: 192.168.1.1-254")
    print(":")
    target_ip_range=input().rstrip()
    scanner.scan_for_devices(target_ip_range)

def enumerate_devices(scanner:Scanner):
    scanner.enumerate_devices()

if __name__ == '__main__':
    scanner=Scanner()
    #erase the file
    with open('pwsd_results.txt', 'w') as f:
        pass
    try:
        while True:
            choice:str=menu(scanner)
            if(choice=='1'):
                scan_for_devices(scanner)
            elif(choice=='2'):
                enumerate_devices(scanner)
            elif(choice=='0'):
                break
            else:
                print("Available options are: ",'1','2','or 0')
                time.sleep(1)
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting...")
        sys.exit(0)
            
    print("Goodbye!")