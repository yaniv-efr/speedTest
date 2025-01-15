import socket
from scapy.all import *
import time

MAGIC_COOKIE = 0xabcddcba
OFFER_MESSAGE_TYPE = 0x2
REQUEST_MESSAGE_TYPE = 0x3
PAYLOAD_MESSAGE_TYPE = 0x4


class OfferMessage(Packet):
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("message_type", OFFER_MESSAGE_TYPE),
        ShortField("udp_port", 0),
        ShortField("tcp_port", 0)
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

def listen_for_offers(udp_port=9999):
    """
    Listens for broadcast offers on the specified UDP port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        udp_socket.bind(("", udp_port))
        print("Client started, listening for offer requests...")
        while True:
            data, addr = udp_socket.recvfrom(1024)  # Buffer size
            try:
                offer = OfferMessage(data)
                if offer.magic_cookie == MAGIC_COOKIE and offer.message_type == OFFER_MESSAGE_TYPE:
                    print(f"Received offer from {addr[0]}")
                    return addr[0], offer.udp_port, offer.tcp_port
                else:
                    print(f"Ignored invalid offer from {addr}")
            except Exception as e:
                print(f"Failed to parse offer from {addr}: {e}")


def color_text(text, color_code):
    """
    Helper function to colorize text using ANSI escape codes.
    :param text: The text to colorize.
    :param color_code: The ANSI color code as a string.
    :return: The colorized text.
    """
    return f"\033[{color_code}m{text}\033[0m"


def handle_udp(server_ip, server_udp_port, file_size, index):
    """
    Handles UDP communication to request and receive a file from the server.
    """
    request = RequestMessage(file_size=file_size)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.settimeout(10)  # 10-second timeout
        try:
            # Send the request message
            udp_socket.sendto(bytes(request), (server_ip, server_udp_port))
            start_time = time.time()

            # Receive the file segments
            data = b""
            segments_received = 0
            while True:
                segment_data, addr = udp_socket.recvfrom(1024)
                payload = PayloadMessage(segment_data)
                segments_received += 1
                if payload.magic_cookie != MAGIC_COOKIE or payload.message_type != PAYLOAD_MESSAGE_TYPE:
                    print(color_text(f"Invalid payload from {addr}", "31"))  # Red text
                    continue
                data += segment_data[len(PayloadMessage()):]  # Extract the payload
                if payload.current_segment == payload.total_segments:
                    break

            end_time = time.time()
            speed = len(data) / (end_time - start_time) / 1024
            segments_received_percentage = (segments_received / payload.total_segments) * 100
            print(
                color_text(
                    f"UDP transfer #{index + 1} finished, total time: {end_time - start_time:.2f} seconds, "
                    f"total speed: {speed:.2f} bits/second, percentage of packets received successfully: "
                    f"{segments_received_percentage:.2f}%",
                    "32",  # Green text
                )
            )
        except socket.timeout:
            print(color_text(f"UDP request to {server_ip}:{server_udp_port} timed out.", "33"))  # Yellow text
        except Exception as e:
            print(color_text(f"Error during UDP communication: {e}", "31"))  # Red text


def handle_tcp(server_ip, server_tcp_port, file_size, index):
    """
    Handles TCP communication to send the file size request and receive the file.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.settimeout(10)  # 10-second timeout
        try:
            tcp_socket.connect((server_ip, server_tcp_port))

            # Send the file size request
            tcp_socket.send(f"{file_size}\n".encode())
            start_time = time.time()

            # Receive the file
            data = b""
            while len(data) < file_size:
                data += tcp_socket.recv(1024)

            end_time = time.time()
            speed = len(data) / (end_time - start_time) / 1024
            print(
                color_text(
                    f"TCP transfer #{index + 1} finished, total time: {end_time - start_time:.2f} seconds, "
                    f"total speed: {speed:.2f} bits/second",
                    "34",  # Blue text
                )
            )
        except socket.timeout:
            print(color_text(f"TCP request to {server_ip}:{server_tcp_port} timed out.", "33"))  # Yellow text
        except Exception as e:
            print(color_text(f"Error during TCP communication: {e}", "31"))  # Red text


def main():
    """
    Main function to handle user input and start the client.
    """
    while True:
        print(color_text("=== New Session ===", "36"))  # Cyan text
        udp_connections = int(input(color_text("Enter number of UDP connections: ", "36")))
        tcp_connections = int(input(color_text("Enter number of TCP connections: ", "36")))
        file_size = int(input(color_text("Enter file size: ", "36")))

        server_ip, server_udp_port, server_tcp_port = listen_for_offers()

        # Store threads in a list
        threads = []

        # Start UDP connection threads
        for i in range(udp_connections):
            thread = threading.Thread(target=handle_udp, args=(server_ip, server_udp_port, file_size, i))
            threads.append(thread)
            thread.start()

        # Start TCP connection threads
        for i in range(tcp_connections):
            thread = threading.Thread(target=handle_tcp, args=(server_ip, server_tcp_port, file_size, i))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        print(color_text("All transfers complete, listening to offer requests\n", "32"))  # Green text


if __name__ == "__main__":
    main()
