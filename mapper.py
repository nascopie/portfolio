#!/usr/bin/env python

#
import sys
import socket
import scapy_http.http

def args():
    if len(sys.argv) != 4:
        print("[*] MAPPER.py ")
        print("[*] Usage: mapper.py <IP> <ports> <verbose>")
        print("[*] <IP> : 127.0.0.1 \n[*] <ports> : 0-65000 \n[*] <verbose> : -v OR -s")
        print("[*] Example: mapper.py 127.0.0.1 0-100 -v")
        sys.exit()


def port_scan(ip, ports, verbose):
    data = ports.split("-")
    start = int(data[0])
    end = int(data[1])
    banner = ""
    open = 0
    close = 0
    for port in range(start,end):
        server = (ip, int(port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(server)
            #try:
                #s.sendall("GET / HTTP/1.0\r\n\r\n")
                #banner = s.recv(2048)
           # except:
                #return
            print("[+] Port " + str(port) + " OPEN")
            #print("    Banner " + banner)
            open = open+1
            s.close()
        except socket.error:
            if verbose == "-v":
                print("[-] Port " + str(port) + " CLOSE")
            close = close+1
    print("[*] There is "+str(open)+" port(s) open")
    print("[*] There is "+str(close)+" port(s) close")


def main():
    args()
    #list_ports = [20, 21, 22, 23, 25, 50, 53, 67, 68, 69, 80, 110, 143, 443, 445, 3389, 8000, 8080, 8081, 9000, 9001]
    ip = sys.argv[1]
    ports = sys.argv[2]
    verbose = sys.argv[3]
    print("[*] Scanning ports " + ports + " on host " + ip)
    port_scan(ip,ports, verbose)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting mapper.py")
        sys.exit(0)
