# Step 03 — Dataset Overview (CICIDS-2017)

## 🎯 Objective
Document the dataset used for training and understand its relevance to the project.

## 💡 Thought Process
The CICIDS-2017 dataset is one of the most widely used benchmarks for network intrusion detection research. It was created by the Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick. The dataset link is provided in the repository README.

## 📊 Dataset Details

### Source
- **Name**: CICIDS-2017 (CIC Intrusion Detection Systems Dataset 2017)
- **Provider**: Canadian Institute for Cybersecurity, UNB
- **Download**: Available via Google Drive link in README
- **Format**: CSV files (one per day of capture)

### Files
| Filename | Description |
|----------|-------------|
| `Monday-WorkingHours.pcap_ISCX.csv` | Normal traffic baseline |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | FTP/SSH brute force attacks |
| `Wednesday-WorkingHours.pcap_ISCX.csv` | DoS attacks (Slowloris, Hulk, GoldenEye) |
| `Thursday-WorkingHours.pcap_ISCX.csv` | Web attacks (SQL injection, XSS, brute force) |
| `Friday-WorkingHours.pcap_ISCX.csv` | DDoS, port scan, botnet |

### Attack Types in Dataset
1. **BENIGN** — Normal legitimate traffic
2. **DDoS** — Distributed Denial of Service
3. **DoS** — Denial of Service (Slowloris, Hulk, GoldenEye, Slowhttptest)
4. **BruteForce** — FTP/SSH brute force attempts
5. **WebAttack** — SQL injection, XSS, brute force
6. **Botnet** — Botnet communication patterns
7. **Recon** — Port scanning and reconnaissance
8. **MITM** — Man-in-the-middle scenarios
9. **Malware** — Malware communication patterns
10. **IoT** — IoT-specific attack patterns

### 22 Selected Features
```
dst_port, protocol, flow_duration, total_packets, total_bytes,
min_pkt_len, max_pkt_len, avg_pkt_len, pkt_len_std, flow_rate,
iat, syn_flag, ack_flag, rst_flag, psh_flag, ttl,
bytes_per_packet, packets_per_second, avg_packet_size,
byte_rate, burstiness, flag_sum
```

### Engineered Features (6 derived)
| Feature | Formula | Purpose |
|---------|---------|---------|
| `bytes_per_packet` | `total_bytes / total_packets` | Average payload density |
| `packets_per_second` | `total_packets / flow_duration` | Traffic velocity |
| `avg_packet_size` | `total_bytes / total_packets` | Mean packet size |
| `byte_rate` | `total_bytes / flow_duration` | Throughput rate |
| `burstiness` | `pkt_len_std / avg_pkt_len` | Traffic variability |
| `flag_sum` | `syn + ack + rst + psh` | TCP flag density |

## ✅ Result
Dataset structure documented. The training pipeline uses 22 features (16 raw + 6 engineered) to classify traffic into 2 binary classes and 10 attack categories.
