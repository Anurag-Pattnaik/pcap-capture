from scapy.all import sniff, IP, TCP, UDP
import requests
import time

API_URL = "http://127.0.0.1:8000/predict"

# =========================
# SIMPLE FLOW TRACKING
# =========================
flow_data = {}

def extract_features(packet):
    try:
        if IP not in packet:
            return None

        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        key = (src, dst, proto)

        if key not in flow_data:
            flow_data[key] = {
                "start_time": time.time(),
                "total_packets": 0,
                "total_bytes": 0
            }

        flow = flow_data[key]

        flow["total_packets"] += 1
        flow["total_bytes"] += len(packet)

        duration = time.time() - flow["start_time"]

        # =========================
        # BUILD FEATURE VECTOR (16)
        # MUST MATCH TRAINING ORDER
        # =========================
        features = [
            packet[IP].dport if hasattr(packet[IP], 'dport') else 0,  # dst_port
            proto,                      # protocol
            duration,                  # flow_duration
            flow["total_packets"],     # total_packets
            flow["total_bytes"],       # total_bytes
            len(packet),               # min_pkt_len (approx)
            len(packet),               # max_pkt_len (approx)
            len(packet),               # avg_pkt_len
            0,                         # pkt_len_std (skip for now)
            flow["total_bytes"] / (duration + 1e-6),  # flow_rate
            duration,                  # iat
            int(TCP in packet and packet[TCP].flags & 0x02),  # syn_flag
            int(TCP in packet and packet[TCP].flags & 0x10),  # ack_flag
            int(TCP in packet and packet[TCP].flags & 0x04),  # rst_flag
            int(TCP in packet and packet[TCP].flags & 0x08),  # psh_flag
            packet[IP].ttl             # ttl
        ]

        return features

    except Exception as e:
        return None


def process_packet(packet):
    features = extract_features(packet)

    if features is None:
        return

    try:
        response = requests.post(API_URL, json={"features": features})
        result = response.json()

        print("🚨 Detection:", result)

    except Exception as e:
        print("API Error:", e)


# =========================
# START SNIFFING
# =========================
print("🚀 Starting Real-Time IDS...")

sniff(prn=process_packet, store=0)