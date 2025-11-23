import scapy.all as scapy
import socket 
import threading
from queue import Queue
import ipaddress

# This function performs an ARP scan for a single IP address.
# It sends an ARP request to the given IP and collects replies.
def scan(ip, result_queue):
    arp_request = scapy.ARP(pdst=ip)               # Create ARP request packet for target IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Create broadcast Ethernet frame
    packet = broadcast/arp_request                # Combine broadcast + ARP into one packet
    answer = scapy.srp(packet, timeout=1, verbose=False)[0]  # Send packet and capture response

    clients = []
    for client in answer:
        client_info = {
            'IP': client[1].psrc,                 # Extract IP of responding device
            'MAC': client[1].hwsrc                # Extract MAC address of device
        }
        # Try resolving hostname via reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(client_info['IP'])[0]
            client_info['Hostname'] = hostname
        except socket.herror:
            client_info['Hostname'] = 'Unknown'    # If lookup fails, set hostname to Unknown
        
        clients.append(client_info)                # Add device info to list

    result_queue.put(clients)                      # Push results into thread-safe queue


# This function prints the final results in a clean table-like format.
def print_result(result):
    print('IP' + " "*20 + 'MAC' + " "*20 + 'Hostname')  # Header
    print('-'*80)                                        # Separator line
    for client in result:
        # Print IP, MAC, and Hostname
        print(client['IP'] + '\t\t' + client['MAC'] + '\t\t' + client['Hostname'])


# Main function that handles network range scanning using threading
def main(cidr):
    results_queue = Queue()                       # Queue for collecting scan results from threads
    threads = []
    network = ipaddress.ip_network(cidr, strict=False)  # Convert input CIDR to network object

    # Create and start a thread for each IP in the network
    for ip in network.hosts():
        thread = threading.Thread(target=scan, args=(str(ip), results_queue))
        thread.start()
        threads.append(thread)
    
    # Wait for all threads to finish
    for thread in threads:
        thread.join()
    
    all_clients = []
    
    # Retrieve all results from the queue
    while not results_queue.empty():
        all_clients.extend(results_queue.get())
    
    # Print all discovered devices
    print_result(all_clients)


# Entry point of the script
if __name__ == '__main__':
    cidr = input("Enter network ip address: ")  # Example input: "192.168.0.0/24"
    main(cidr)
