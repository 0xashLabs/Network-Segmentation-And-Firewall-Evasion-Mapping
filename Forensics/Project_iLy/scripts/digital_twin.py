#!/usr/bin/env python3
import socket
import struct
import time
import sys

# Define CAN frame structure: 32-bit CAN ID, 8-bit DLC, 3 bytes padding, 8 bytes payload
CAN_FRAME_FMT = "=IB3x8s"

def send_can_frame(sock, interface, can_id, data):
    """
    Sends a single CAN frame to the specified interface using raw sockets.
    """
    # Pad data to 8 bytes
    data = data.ljust(8, b'\x00')
    dlc = len(data)
    frame = struct.pack(CAN_FRAME_FMT, can_id, dlc, data)
    try:
        sock.send(frame)
        print(f"Sent CAN ID {hex(can_id)} [{dlc} bytes]: {data.hex().upper()}")
    except Exception as e:
        print(f"Error sending frame: {e}", file=sys.stderr)

def main():
    print("Project iLy - Digital Twin Simulation Script")
    print("============================================")
    
    interface = "vcan0"
    is_socketcan_supported = False
    
    # Try to initialize raw CAN socket
    sock = None
    if hasattr(socket, "AF_CAN"):
        try:
            sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            sock.bind((interface,))
            is_socketcan_supported = True
            print(f"Connected successfully to CAN interface: {interface}")
        except Exception as e:
            print(f"Warning: Could not bind to interface '{interface}' ({e}).")
            print("Running in simulation mode (printing candump format output to stdout).")
    else:
        print("Note: socket.AF_CAN not available on this platform (likely Windows/macOS).")
        print("Running in simulation mode (printing candump format output to stdout).")

    # Define a sequence of simulation events
    # Elements: (relative_timestamp, can_id, payload_bytes, comment)
    # 0x200: Brake state (Byte 0: 0x00=Released, 0x01=Pressed)
    # 0x201: Speed/RPM (Byte 0-1: Speed, Byte 2-3: RPM)
    # 0x300: Diagnostics (Byte 0: Session Type)
    # 0x150: Airbag / Impact Trigger (Byte 0: Deploy Flag)
    simulation_events = [
        # 1. Normal Operation
        (0.0, 0x201, b'\x2D\x00\x0B\xB8', "Normal driving: Speed=45mph, RPM=3000"),
        (0.5, 0x200, b'\x00',             "Brake pedal: Released"),
        
        # 2. Compromise/Spoofing Phase
        (1.0, 0x300, b'\x03',             "Anomaly: Diagnostic session opened while driving (0x300)"),
        (1.2, 0x200, b'\x00',             "Spoofed brake message injected: Brakes=Released (0x200)"),
        
        # 3. Crash Phase
        (1.5, 0x201, b'\x20\x00\x09\xC4', "Impact Imminent: Speed reduced to 32mph, RPM=2500"),
        (1.8, 0x150, b'\x01',             "Airbag deployment / collision impact frame (0x150)")
    ]

    print("\nStarting playback of simulated accident sequence...")
    start_time = time.time()
    
    for rel_time, can_id, data, comment in simulation_events:
        # Sleep until the relative time is reached
        elapsed = time.time() - start_time
        sleep_needed = rel_time - elapsed
        if sleep_needed > 0:
            time.sleep(sleep_needed)
            
        current_epoch = time.time()
        
        if is_socketcan_supported and sock:
            send_can_frame(sock, interface, can_id, data)
        else:
            # Output in candump syntax: (timestamp) interface ID#payload
            hex_data = data.hex().upper()
            hex_id = f"{can_id:03X}"
            candump_str = f"({current_epoch:.6f}) {interface} {hex_id}#{hex_data}"
            print(f"{candump_str}   ; {comment}")

    print("\nSimulation complete.")
    if sock:
        sock.close()

if __name__ == "__main__":
    main()
