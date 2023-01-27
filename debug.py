import socket
import time

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Define the target IP and port
ip = "127.0.0.1"
port = 8000

# Send the packets in a loop
while True:
    # Create the message to send
    message = b"This is a debug packet"
    # Send the packet
    sock.sendto(message, (ip, port))
    # Print a message to indicate that the packet was sent
    print(f"Sent packet to {ip}:{port}")
    # Wait for a short time before sending the next packet
    time.sleep(1)
