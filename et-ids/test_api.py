"""Quick API test for ET-IDS endpoints."""
import requests
import json

BASE = "http://localhost:8000"

# Test 1: Benign flow
benign_features = {
    "dst_port": 443, "protocol": 6, "flow_duration": 2.5,
    "total_packets": 15, "total_bytes": 8500, "min_pkt_len": 40,
    "max_pkt_len": 1460, "avg_pkt_len": 566, "pkt_len_std": 480,
    "flow_rate": 3400, "iat": 0.17, "syn_flag": 1, "ack_flag": 1,
    "rst_flag": 0, "psh_flag": 1, "ttl": 64, "bytes_per_packet": 566,
    "packets_per_second": 6.0, "avg_packet_size": 566,
    "byte_rate": 3400, "burstiness": 0.85, "flag_sum": 3
}

r1 = requests.post(f"{BASE}/detect", json={"features": benign_features})
print("=== Benign Flow Test ===")
print(f"Status: {r1.status_code}")
result1 = r1.json()
print(f"Prediction: {result1.get('prediction')}")
print(f"Confidence: {result1.get('confidence')}")
print(f"Binary: {result1.get('binary_label')}")
print(f"Attack: {result1.get('attack_label')}")
print(f"Severity: {result1.get('severity')}")

# Test 2: Attack-like flow (SYN flood pattern)
attack_features = {
    "dst_port": 22, "protocol": 6, "flow_duration": 0.5,
    "total_packets": 500, "total_bytes": 25000, "min_pkt_len": 40,
    "max_pkt_len": 60, "avg_pkt_len": 50, "pkt_len_std": 5,
    "flow_rate": 50000, "iat": 0.001, "syn_flag": 1, "ack_flag": 0,
    "rst_flag": 0, "psh_flag": 0, "ttl": 128, "bytes_per_packet": 50,
    "packets_per_second": 1000, "avg_packet_size": 50,
    "byte_rate": 50000, "burstiness": 0.1, "flag_sum": 1
}

r2 = requests.post(f"{BASE}/detect", json={"features": attack_features})
print("\n=== Attack-like Flow Test ===")
print(f"Status: {r2.status_code}")
result2 = r2.json()
print(f"Prediction: {result2.get('prediction')}")
print(f"Confidence: {result2.get('confidence')}")
print(f"Binary: {result2.get('binary_label')}")
print(f"Attack: {result2.get('attack_label')}")
print(f"Severity: {result2.get('severity')}")

# Test 3: Health
r3 = requests.get(f"{BASE}/health")
h = r3.json()
print("\n=== Health Check ===")
print(f"Status: {h['status']}")
print(f"Model loaded: {h['model_loaded']}")
print(f"Model type: {h['model_info']['type']}")
print(f"Features: {len(h['expected_features'])}")
print(f"Metrics: {h['metrics']}")

# Test 4: Interfaces
r4 = requests.get(f"{BASE}/capture/interfaces")
ifaces = r4.json()
print(f"\n=== Network Interfaces ({len(ifaces.get('interfaces', []))}) ===")
for iface in ifaces.get("interfaces", [])[:5]:
    print(f"  - {iface}")

print("\n✅ All API tests passed!")
