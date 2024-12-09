from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
 
# Konfiguracja serwera DHCP
DHCP_SERVER_IP = "192.168.1.1" #Dostosowac
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 86400  # 24 godziny
DNS_SERVER = "8.8.8.8"
 
# Zarządzanie adresami IP
ip_pool = [f"192.168.1.{i}" for i in range(100, 200)]  # Pula dostępnych adresów
leased_ips = {}  # Przypisane adresy: {MAC: (IP, expiration_time)}
 
 
def allocate_ip(client_mac):
    # Sprawdź, czy klient już ma przypisany adres
    if client_mac in leased_ips:
        ip, expiration_time = leased_ips[client_mac]
        if expiration_time > time.time():  # Jeśli dzierżawa jest aktywna
            return ip
 
    # Przydziel nowy adres z puli
    if ip_pool:
        ip = ip_pool.pop(0)
        leased_ips[client_mac] = (ip, time.time() + LEASE_TIME)
        return ip
    else:
        print("ERROR: Brak dostępnych adresów IP.")
        return None
 
 
def release_ip(client_mac):
    """
    Zwolnienie adresu IP przypisanego do klienta.
    """
    if client_mac in leased_ips:
        ip, _ = leased_ips.pop(client_mac)
        ip_pool.append(ip)
        print(f"DEBUG: Zwolniono adres IP={ip} przypisany do MAC={client_mac}")
 
 #Obsluga DHCP discover
def handle_dhcp_discover(packet):
 
    transaction_id = packet[BOOTP].xid
    client_mac = packet[Ether].src
    offered_ip = allocate_ip(client_mac)
 
    if not offered_ip:
        return
 
    print(f"DEBUG: Otrzymano DISCOVER od {client_mac}, przydzielono IP={offered_ip}")
    send_dhcp_offer(transaction_id, client_mac, offered_ip)
 
  #Obsluga DHCP request
def handle_dhcp_request(packet):
    """
    Obsługuje wiadomość DHCP REQUEST.
    """
    transaction_id = packet[BOOTP].xid
    client_mac = packet[Ether].src
 
    # Pobierz żądany adres IP z opcji Requested IP Address
    requested_ip = None
    for option in packet[DHCP].options:
        if option[0] == "requested_addr":
            requested_ip = option[1]
            break
 
    if not requested_ip:
        print("ERROR: Brak opcji 'requested_addr' w pakiecie REQUEST.")
        return
 
    # Sprawdź, czy adres IP jest dostępny
    if client_mac in leased_ips and leased_ips[client_mac][0] == requested_ip:
        print(f"DEBUG: Potwierdzono REQUEST dla IP={requested_ip} od {client_mac}")
        send_dhcp_ack(transaction_id, client_mac, requested_ip)
    else:
        print(f"ERROR: Adres IP={requested_ip} nie jest dostępny dla MAC={client_mac}.")
        send_dhcp_nak(transaction_id, client_mac)
 
#Wysyłanie DHCP OFFER
def send_dhcp_offer(transaction_id, client_mac, offered_ip):
    dhcp_offer = Ether(dst=client_mac, src=get_if_hwaddr(conf.iface)) / \
                 IP(src=DHCP_SERVER_IP, dst="255.255.255.255") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr=offered_ip, siaddr=DHCP_SERVER_IP, chaddr=mac2str(client_mac), xid=transaction_id) / \
                 DHCP(options=[
                     ("message-type", "offer"),
                     ("server_id", DHCP_SERVER_IP),
                     ("subnet_mask", SUBNET_MASK),
                     ("router", DHCP_SERVER_IP),
                     ("lease_time", LEASE_TIME),
                     ("name_server", DNS_SERVER),
                     "end"
                 ])
    sendp(dhcp_offer, iface=conf.iface, verbose=1)
 
 #Wysyłanie DHCP ACK
def send_dhcp_ack(transaction_id, client_mac, assigned_ip):
    dhcp_ack = Ether(dst=client_mac, src=get_if_hwaddr(conf.iface)) / \
               IP(src=DHCP_SERVER_IP, dst="255.255.255.255") / \
               UDP(sport=67, dport=68) / \
               BOOTP(op=2, yiaddr=assigned_ip, siaddr=DHCP_SERVER_IP, chaddr=mac2str(client_mac), xid=transaction_id) / \
               DHCP(options=[
                   ("message-type", "ack"),
                   ("server_id", DHCP_SERVER_IP),
                   ("subnet_mask", SUBNET_MASK),
                   ("router", DHCP_SERVER_IP),
                   ("lease_time", LEASE_TIME),
                   ("name_server", DNS_SERVER),
                   "end"
               ])
    sendp(dhcp_ack, iface=conf.iface, verbose=1)
 
#Wysyłanie DHCP NAK
def send_dhcp_nak(transaction_id, client_mac):
 
    dhcp_nak = Ether(dst=client_mac, src=get_if_hwaddr(conf.iface)) / \
               IP(src=DHCP_SERVER_IP, dst="255.255.255.255") / \
               UDP(sport=67, dport=68) / \
               BOOTP(op=2, siaddr=DHCP_SERVER_IP, chaddr=mac2str(client_mac), xid=transaction_id) / \
               DHCP(options=[
                   ("message-type", "nak"),
                   ("server_id", DHCP_SERVER_IP),
                   "end"
               ])
    print(f"DEBUG: Wysłano NAK do MAC={client_mac}, Transaction ID={transaction_id}")
    sendp(dhcp_nak, iface=conf.iface, verbose=1)
 
 
def dhcp_server():
 
    print("Serwer DHCP nasłuchuje...")
    sniff(filter="udp and (port 67 or port 68)", prn=handle_packet, store=0)
 
 
def handle_packet(packet):
    if DHCP in packet:
        dhcp_message_type = [option[1] for option in packet[DHCP].options if option[0] == "message-type"][0]
        if dhcp_message_type == 1:  # DISCOVER
            handle_dhcp_discover(packet)
        elif dhcp_message_type == 3:  # REQUEST
            handle_dhcp_request(packet)
 
 
if __name__ == "__main__":
    dhcp_server()
