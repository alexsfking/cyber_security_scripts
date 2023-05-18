#!/usr/bin/python
import sys
import os
import nmap
import time


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
        self.nm.scan(target_ip_range, arguments='-sn')
        for host in self.nm.all_hosts():
            self.available_hosts.add(host)

    def enumerate_devices(self):
        #nmap -p- --script http-title 192.168.159.137
        for host in self.available_hosts:
            print("Checking: ", host)
            response = os.system("ping -c 1 " + host + " > /dev/null 2>&1")
            if response == 0:
                self.nm.scan(hosts=host, arguments='-p 1-65535 --script=http-title,http-server-header,http-methods,http-headers,http-enum')
                if 'tcp' in self.nm[host]:
                    #print(f"Open ports for {host}:")
                    for port in self.nm[host]['tcp']:
                        headers,title,server_header,methods,enum=None,None,None,None,None
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            if 'script' in self.nm[host]['tcp'][port]:
                                if 'http-headers' in self.nm[host]['tcp'][port]['script']:
                                    headers = self.nm[host]['tcp'][port]['script']['http-headers']
                                if 'http-title' in self.nm[host]['tcp'][port]['script']:
                                    title = self.nm[host]['tcp'][port]['script']['http-title']
                                if 'http-server-header' in self.nm[host]['tcp'][port]['script']:
                                    server_header = self.nm[host]['tcp'][port]['script']['http-server-header']
                                if 'http-methods' in self.nm[host]['tcp'][port]['script']:
                                    methods = self.nm[host]['tcp'][port]['script']['http-methods']
                                if 'http-enum' in self.nm[host]['tcp'][port]['script']:
                                    enum = self.nm[host]['tcp'][port]['script']['http-enum']

                            if self.nm[host]['tcp'][port]['name'] == 'http' or headers or title or server_header or methods:
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
            
    print("Goodbye!")