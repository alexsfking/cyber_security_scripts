#!/usr/bin/env/python
import nmap
import os
import sys
import time

'''
The shebang line #!/usr/bin/env/python specifies the interpreter to be used to
run the script (in this case, the python command).

The necessary imports are made: nmap, os, sys, and time.

The script defines a class called Scanner which is used for scanning and
enumerating devices.

In the __init__ method of the Scanner class, an instance of nmap.PortScanner is
created. If an error occurs during the creation of the PortScanner object, an
appropriate error message is printed, and the script exits.

The scan_for_devices method of the Scanner class takes an IP range as input and
uses nmap to scan for devices in that range. The -sn argument in the scan method
indicates a ping scan, which determines if hosts are online. The IP addresses of
available hosts are stored in the available_hosts set.

The enumerate_devices method iterates over the available hosts and performs
various checks on each host. First, it checks if the host is reachable by
pinging it. If the host is reachable, it performs a detailed scan using nmap
with specific arguments (-p 1-65535
--script=http-title,http-server-header,http-methods,http-headers,http-enum) to
gather information about the web server running on the host. The script then
extracts various data such as headers, title, server header, methods, and
enumeration results if available. Finally, the method outputs the results to
both the standard output and a file named "pwsd_results.txt".

The extract_script_data method extracts relevant data from the script object
obtained from the nmap scan. If the script data is available, it returns the
extracted information; otherwise, it returns None.

The output_http_results_to_file method writes the HTTP scan results to the
"pwsd_results.txt" file. It formats the results and writes them to the file
using the write method.

The output_http_results_to_stdout method prints the HTTP scan results to the
standard output. It formats the results and prints them using the print
function.

The menu function displays a menu for the user to interact with. It prints the
menu options and takes user input. The chosen option is returned as a string.

The scan_for_devices function prompts the user to enter an IP range to scan for
devices. It takes the input, calls the scan_for_devices method of the Scanner
object, and performs the scan.

The enumerate_devices function calls the enumerate_devices method of the Scanner
object to enumerate the detected devices and gather information about their web
servers.

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

    def scan_for_devices(self,target_ip_range:str):
        #nmap -sn 192.168.159.1-254
        #nmap -sn 192.168.159.137
        self.nm.scan(target_ip_range, arguments='-sn')
        for host in self.nm.all_hosts():
            self.available_hosts.add(host)

    def enumerate_devices(self):
        #nmap 192.168.159.137 -p 1-65535 --script=http-title,http-server-header,http-methods,http-headers,http-enum
        for host in self.available_hosts:
            print("Checking: ", host)
            with open('pwsd_results.txt', 'a') as f:
                f.write("Checking: " + str(host) + "\n")
            response = os.system("ping -c 1 " + host + " > /dev/null 2>&1")
            if response == 0:
                self.nm.scan(hosts=host, arguments='-p 1-65535 --script=http-title,http-server-header,http-methods,http-headers,http-enum')
                if 'tcp' in self.nm[host]:
                    #print(f"Open ports for {host}:")
                    for port in self.nm[host]['tcp']:
                        headers,title,server_header,methods,enum=None,None,None,None,None
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            script_data = self.extract_script_data(host, port)
                            if script_data:
                                headers, title, server_header, methods, enum = script_data
                            if self.nm[host]['tcp'][port]['name'] == 'http' or headers or title or server_header or methods:
                                self.output_http_results_to_stdout(host,port,headers,title,server_header,methods,enum)
                                self.output_http_results_to_file(host,port,headers,title,server_header,methods,enum)

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