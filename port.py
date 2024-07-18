import nmap
import ipaddress

def scan_ports(ip__range):
    nm = nmap.PortScanner()


    try:
        # Scan the IP Range
        nm.scan(ip__range,'1-1024') #Scanning the 1024 first ports


        for host in nm.all_hosts():
            print(f'Scanning IP: {host}')
            print(f'Host : {host} ({nm[host].hostname()})')
            print(f'State : {nm[host].state()}')


            for proto in nm[host].all_protocols():
                print('-------------')
                print(f'Protocol : {proto}')


                lport = nm[host][proto].keys()
                for port in lport:
                    print(f'Port : {port}\tState : {nm[host][proto][port]["state"]}\tService : {nm[host][proto][port]["name"]}')


    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":

    #Using Example
    ip_range = input("Enter the IP address or range (CIDR format): ")
    try:
    # Validate IP Range 
         ipaddress.ip_network(ip_range)
         scan_ports(ip_range)
    except ValueError as e :
        print(f"Invalid Ip range: {e}")                             
