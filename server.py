from scapy.all import *
import threading
import time
import os

server_ip = "192.168.1.179"
tcp_port = 63333
udp_port = 11375
broadcast_address = "192.168.1.255"
tcp_socket_size = 50
stats_speed = 10  # In seconds

MAGIC_COOKIE = 0xabcddcba
OFFER_MESSAGE_TYPE = 0x2
REQUEST_MESSAGE_TYPE = 0x3
PAYLOAD_MESSAGE_TYPE = 0x4

# Statistics dictionary
stats = {
    "total_udp_requests": 0,
    "total_tcp_requests": 0,
    "total_data_sent": 0,  # In bytes
    "average_udp_speed": 0.0,  # In KB/s
    "average_tcp_speed": 0.0,  # In KB/s
}


class OfferMessage(Packet):
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("message_type", OFFER_MESSAGE_TYPE),
        ShortField("udp_port", udp_port),
        ShortField("tcp_port", tcp_port)
    ]


class RequestMessage(Packet):
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("message_type", REQUEST_MESSAGE_TYPE),
        LongField("file_size", 0)
    ]


class PayloadMessage(Packet):
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("message_type", PAYLOAD_MESSAGE_TYPE),
        LongField("total_segments", 0),
        LongField("current_segment", 0)
    ]


def print_stats():
    """
    Periodically prints the collected statistics.
    """
    while True:
        time.sleep(stats_speed)  # Print stats every 10 seconds
        print("\n=== Server Statistics ===")
        print(f"Total UDP Requests: {stats['total_udp_requests']}")
        print(f"Total TCP Requests: {stats['total_tcp_requests']}")
        print(f"Total Data Sent: {stats['total_data_sent']} bytes")
        print("=========================\n")


def create_offer_message():
    return bytes(OfferMessage())


def broadcast():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((server_ip, 0))
        while True:
            try:
                udp_socket.sendto(create_offer_message(), (broadcast_address, 9999))
                time.sleep(1)
            except OSError as e:
                print(f"Broadcast error: {e}")
                break


def handle_udp_request(udp_socket):
    while True:
        try:
            data, client_address = udp_socket.recvfrom(2048)
            request = RequestMessage(data)
            if request.magic_cookie != MAGIC_COOKIE or request.message_type != REQUEST_MESSAGE_TYPE:
                print(f"Invalid request from {client_address}")
                continue
            stats["total_udp_requests"] += 1
            threading.Thread(
                target=send_udp_file,
                args=(client_address[0], client_address[1], request.file_size),
                daemon=True
            ).start()
        except Exception as e:
            print(f"Error handling UDP request: {e}")
            continue


def send_udp_file(client_ip, client_port, file_size):
    data = os.urandom(file_size)
    total_segments = (file_size // 1024) + 1
    current_segment = 0

    start_time = time.time()
    while len(data) > 0:
        current_segment += 1
        payload = data[:1024]
        data = data[1024:]

        payload_packet = (
            IP(dst=client_ip) /
            UDP(sport=udp_port, dport=client_port) /
            PayloadMessage(
                total_segments=total_segments,
                current_segment=current_segment
            ) /
            Raw(load=payload)
        )
        send(payload_packet, verbose=False)
    end_time = time.time()

    # Update stats
    speed = file_size / (end_time - start_time) / 1024
    stats["total_data_sent"] += file_size
    stats["average_udp_speed"] = ((stats["average_udp_speed"] * (stats["total_udp_requests"] - 1)) + speed) / stats["total_udp_requests"]


def handle_tcp_connection(tcp_socket):
    tcp_socket.listen(tcp_socket_size)
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(
            target=send_tcp_file,
            args=(client_socket, client_address),
            daemon=True
        ).start()


def send_tcp_file(client_socket, client_address):
    with client_socket:
        try:
            file_size = int(client_socket.recv(1024).decode().strip())
            stats["total_tcp_requests"] += 1

            data = os.urandom(file_size)
            start_time = time.time()
            client_socket.sendall(data)
            end_time = time.time()

            speed = file_size / (end_time - start_time) / 1024
            stats["total_data_sent"] += file_size
            stats["average_tcp_speed"] = ((stats["average_tcp_speed"] * (stats["total_tcp_requests"] - 1)) + speed) / stats["total_tcp_requests"]
        except Exception as e:
            print(f"Error sending file to {client_address}: {e}")


def main():
    threading.Thread(target=broadcast, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    print("Server started, listening on IP address:", server_ip)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((server_ip, udp_port))

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((server_ip, tcp_port))

    threading.Thread(target=handle_udp_request, args=(udp_socket,), daemon=True).start()
    threading.Thread(target=handle_tcp_connection, args=(tcp_socket,), daemon=True).start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
