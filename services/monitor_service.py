import threading
import time
import random
from datetime import datetime, timezone
import socket

# Try importing scapy components
try:
    from scapy.all import get_if_list, sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Global Sniffer Singleton State
class NetworkSnifferManager:
    def __init__(self):
        self.is_monitoring = False
        self.active_session_id = None
        self.interface = None
        self.packets_buffer = []
        self.buffer_lock = threading.Lock()
        self.thread = None
        self.use_simulation = False
        self.permission_warning = False

    def get_interfaces(self):
        """Fetch available network interfaces. Fallback to loopbacks if Scapy errors out."""
        if SCAPY_AVAILABLE:
            try:
                ifaces = get_if_list()
                if ifaces and len(ifaces) > 0:
                    return ifaces
            except Exception:
                pass
        
        # Fallback list for offline / non-scapy / permission-restricted environments
        return [
            "Loopback Pseudo-Interface 1",
            "Ethernet Adapter (Local Area Connection)",
            "Wireless Network Adapter (Wi-Fi 0)",
            "VirtualBox Host-Only Network"
        ]

    def start_monitoring(self, interface, session_id):
        """Start packet capture on the selected interface in a background thread."""
        self.is_monitoring = True
        self.active_session_id = session_id
        self.interface = interface
        self.packets_buffer = []
        self.permission_warning = False
        self.use_simulation = False

        # Start thread
        self.thread = threading.Thread(target=self._run_sniffing, daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        """Stop packet capture thread."""
        self.is_monitoring = False
        if self.thread:
            self.thread.join(timeout=2.0)
        return len(self.packets_buffer)

    def retrieve_new_packets(self):
        """Flush buffer and retrieve all packets captured since last poll."""
        with self.buffer_lock:
            packets = list(self.packets_buffer)
            self.packets_buffer.clear()
        return packets

    def _run_sniffing(self):
        """Background sniffer loop. Automatically switches to simulation if raw sockets fail."""
        if not SCAPY_AVAILABLE:
            self.use_simulation = True
            self.permission_warning = True
            self._run_simulation()
            return

        # Attempt to capture real packets using Scapy
        try:
            # Short test sniff to verify privileges
            sniff(iface=self.interface, count=1, timeout=0.5)
        except Exception as e:
            # Permission denied or npcap driver missing
            self.use_simulation = True
            self.permission_warning = True
            print(f"[MONITOR] Permission denied or driver missing: {str(e)}. Falling back to simulation mode.")
            self._run_simulation()
            return

        # Start real Scapy sniffer loop
        def packet_handler(pkt):
            if not self.is_monitoring:
                return

            # Extract basic packet specification
            src = "0.0.0.0"
            dst = "0.0.0.0"
            proto = "Other"
            length = len(pkt)

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                if TCP in pkt:
                    proto = "TCP"
                elif UDP in pkt:
                    proto = "UDP"
                elif ICMP in pkt:
                    proto = "ICMP"
            elif ARP in pkt:
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto = "ARP"

            packet_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src": src,
                "dst": dst,
                "protocol": proto,
                "length": length
            }

            with self.buffer_lock:
                self.packets_buffer.append(packet_data)

        try:
            # Sniff in blocks with short timeouts to regularly check check-stop condition
            while self.is_monitoring:
                sniff(iface=self.interface, prn=packet_handler, count=10, timeout=1.0, store=False)
        except Exception:
            # Fallback to simulation if errors occur midway
            self.use_simulation = True
            self._run_simulation()

    def _run_simulation(self):
        """Generates realistic local loopback and subnet traffic for display and charts."""
        mock_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.1", "10.0.0.5", "10.0.0.1",
            "172.16.0.4", "8.8.8.8", "1.1.1.1", "18.224.2.14", "142.250.190.46"
        ]
        protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "ARP"]
        
        while self.is_monitoring:
            # Sleep standard TCP packet interval
            time.sleep(random.uniform(0.1, 0.4))
            
            src = random.choice(mock_ips)
            # Ensure dest is different
            dst = random.choice(mock_ips)
            while dst == src:
                dst = random.choice(mock_ips)
                
            proto = random.choice(protocols)
            length = random.randint(40, 1500)
            
            packet_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src": src,
                "dst": dst,
                "protocol": proto,
                "length": length
            }
            
            with self.buffer_lock:
                # Caps buffer size to prevent memory exhaustion if client stops polling
                if len(self.packets_buffer) < 1000:
                    self.packets_buffer.append(packet_data)


# Instantiate sniffer manager singleton
sniffer_manager = NetworkSnifferManager()
