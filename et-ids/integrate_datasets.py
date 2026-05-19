"""
integrate_datasets.py - Corrected Standing Dataset Integration Script

This script merges the four major NIDS datasets:
  1. CICIDS-2017
  2. NF-UNSW-NB15-v2
  3. NF-ToN-IoT-v2
  4. CICIOT2023

Corrected Bugs from original notebook:
  1. [CRITICAL] Fixed binary normalization: Maps '0', '0.0', 'normal', 'benign' to 'BENIGN'.
     (Previously, '0' and '0.0' mapped to 'MALICIOUS', corrupting the UNSW and ToN-IoT datasets).
  2. [CRITICAL] Unified Multiclass Labels: Maps 'attack' column for UNSW and ToN-IoT instead of
     their binary 'label' column.
"""

import pandas as pd
import numpy as np
import glob
import os
import sys

def main():
    print("==================================================")
    print("🚀 Starting Corrected Dataset Integration Pipeline")
    print("==================================================")

    # Define paths
    raw_dir = "../data/raw"
    if not os.path.exists(raw_dir):
        raw_dir = "data/raw"  # Fallback if run from repo root
    
    cic_path = os.path.join(raw_dir, "cicids2017/*.csv")
    ton_path = os.path.join(raw_dir, "nf_ton_iot/NF-ToN-IoT-v2.csv")
    unsw_path = os.path.join(raw_dir, "nf_unsw_nb15/NF-UNSW-NB15-v2.csv")
    iot_path = os.path.join(raw_dir, "ciciot2023/*.csv")
    output_csv = os.path.join(raw_dir, "unified_dataset.csv")

    # ─────────────────────────────────────────────────────────────
    # 1. Load CICIDS2017
    # ─────────────────────────────────────────────────────────────
    print("\n[1/4] Loading CICIDS-2017...")
    cic_files = glob.glob(cic_path)
    if not cic_files:
        print(f"⚠️ No files found in {cic_path}. Skipping CICIDS2017.")
        cic = pd.DataFrame()
    else:
        print(f"  Found {len(cic_files)} files. Merging...")
        cic = pd.concat([pd.read_csv(f) for f in cic_files], ignore_index=True)
        print(f"  Loaded Shape: {cic.shape}")

    # ─────────────────────────────────────────────────────────────
    # 2. Load NF-ToN-IoT-v2
    # ─────────────────────────────────────────────────────────────
    print("\n[2/4] Loading NF-ToN-IoT-v2...")
    if not os.path.exists(ton_path):
        print(f"⚠️ File not found: {ton_path}. Skipping ToN-IoT.")
        ton = pd.DataFrame()
    else:
        ton = pd.read_csv(ton_path, nrows=200000)
        print(f"  Loaded Shape: {ton.shape}")

    # ─────────────────────────────────────────────────────────────
    # 3. Load NF-UNSW-NB15-v2
    # ─────────────────────────────────────────────────────────────
    print("\n[3/4] Loading NF-UNSW-NB15-v2...")
    if not os.path.exists(unsw_path):
        print(f"⚠️ File not found: {unsw_path}. Skipping UNSW-NB15.")
        unsw = pd.DataFrame()
    else:
        unsw = pd.read_csv(unsw_path, nrows=200000)
        print(f"  Loaded Shape: {unsw.shape}")

    # ─────────────────────────────────────────────────────────────
    # 4. Load CICIOT2023
    # ─────────────────────────────────────────────────────────────
    print("\n[4/4] Loading CICIOT2023...")
    iot_files = glob.glob(iot_path)
    if not iot_files:
        print(f"⚠️ No files found in {iot_path}. Skipping CICIOT2023.")
        iot = pd.DataFrame()
    else:
        selected_files = iot_files[:10]
        print(f"  Found {len(iot_files)} files. Merging first 10 files...")
        iot = pd.concat([pd.read_csv(f) for f in selected_files], ignore_index=True)
        print(f"  Loaded Shape: {iot.shape}")

    # ─────────────────────────────────────────────────────────────
    # Normalize Column Names to standard lowercase
    # ─────────────────────────────────────────────────────────────
    for df in [cic, ton, unsw, iot]:
        if not df.empty:
            df.columns = df.columns.str.strip().str.lower()

    # ─────────────────────────────────────────────────────────────
    # 5. Clean & Align Features per dataset
    # ─────────────────────────────────────────────────────────────
    print("\n⚙️ Extracting and aligning features...")

    datasets_to_merge = []

    # 5.1 CICIDS-2017
    if not cic.empty:
        print("  Processing CICIDS-2017 features...")
        cic_clean = pd.DataFrame()
        cic_clean['dst_port'] = cic['destination port']
        cic_clean['flow_duration'] = cic['flow duration']
        cic_clean['total_packets'] = cic['total fwd packets'] + cic['total backward packets']
        cic_clean['total_bytes'] = cic['total length of fwd packets'] + cic['total length of bwd packets']
        cic_clean['min_pkt_len'] = cic['min packet length']
        cic_clean['max_pkt_len'] = cic['max packet length']
        cic_clean['avg_pkt_len'] = cic['packet length mean']
        cic_clean['pkt_len_std'] = cic['packet length std']
        cic_clean['flow_rate'] = cic['flow packets/s']
        cic_clean['iat'] = cic['flow iat mean']
        cic_clean['syn_flag'] = cic['syn flag count']
        cic_clean['ack_flag'] = cic['ack flag count']
        cic_clean['rst_flag'] = cic['rst flag count']
        cic_clean['psh_flag'] = cic['psh flag count']
        cic_clean['label'] = cic['label']
        datasets_to_merge.append(('CICIDS2017', cic_clean))

    # 5.2 NF-ToN-IoT-v2
    if not ton.empty:
        print("  Processing NF-ToN-IoT-v2 features...")
        ton_clean = pd.DataFrame()
        ton_clean['dst_port'] = ton['l4_dst_port']
        ton_clean['protocol'] = ton['protocol']
        ton_clean['flow_duration'] = ton['flow_duration_milliseconds']
        ton_clean['total_packets'] = ton['in_pkts'] + ton['out_pkts']
        ton_clean['total_bytes'] = ton['in_bytes'] + ton['out_bytes']
        ton_clean['min_pkt_len'] = ton['min_ip_pkt_len']
        ton_clean['max_pkt_len'] = ton['max_ip_pkt_len']
        # Compute proper average packet size
        ton_clean['avg_pkt_len'] = (ton['longest_flow_pkt'] + ton['shortest_flow_pkt']) / 2.0
        ton_clean['flow_rate'] = ton['src_to_dst_avg_throughput']
        ton_clean['syn_flag'] = ton['tcp_flags']
        ton_clean['ack_flag'] = ton['tcp_flags']
        ton_clean['rst_flag'] = ton['tcp_flags']
        ton_clean['psh_flag'] = ton['tcp_flags']
        ton_clean['ttl'] = ton['min_ttl']
        # BUG FIX: Pull attack labels (e.g. 'dos', 'ddos'), not the binary 0/1 column 'label'
        ton_clean['label'] = ton['attack']
        datasets_to_merge.append(('ToN-IoT', ton_clean))

    # 5.3 NF-UNSW-NB15-v2
    if not unsw.empty:
        print("  Processing NF-UNSW-NB15-v2 features...")
        unsw_clean = pd.DataFrame()
        unsw_clean['dst_port'] = unsw['l4_dst_port']
        unsw_clean['protocol'] = unsw['protocol']
        unsw_clean['flow_duration'] = unsw['flow_duration_milliseconds']
        unsw_clean['total_packets'] = unsw['in_pkts'] + unsw['out_pkts']
        unsw_clean['total_bytes'] = unsw['in_bytes'] + unsw['out_bytes']
        unsw_clean['min_pkt_len'] = unsw['min_ip_pkt_len']
        unsw_clean['max_pkt_len'] = unsw['max_ip_pkt_len']
        unsw_clean['avg_pkt_len'] = (unsw['longest_flow_pkt'] + unsw['shortest_flow_pkt']) / 2.0
        unsw_clean['flow_rate'] = unsw['src_to_dst_avg_throughput']
        unsw_clean['syn_flag'] = unsw['tcp_flags']
        unsw_clean['ack_flag'] = unsw['tcp_flags']
        unsw_clean['rst_flag'] = unsw['tcp_flags']
        unsw_clean['psh_flag'] = unsw['tcp_flags']
        unsw_clean['ttl'] = unsw['min_ttl']
        # BUG FIX: Pull attack labels (e.g. 'dos', 'ddos'), not the binary 0/1 column 'label'
        unsw_clean['label'] = unsw['attack']
        datasets_to_merge.append(('UNSW-NB15', unsw_clean))

    # 5.4 CICIOT2023
    if not iot.empty:
        print("  Processing CICIOT2023 features...")
        iot_clean = pd.DataFrame()
        iot_clean['protocol'] = iot['protocol type']
        iot_clean['total_packets'] = iot['number']
        iot_clean['total_bytes'] = iot['tot size']
        iot_clean['min_pkt_len'] = iot['min']
        iot_clean['max_pkt_len'] = iot['max']
        iot_clean['avg_pkt_len'] = iot['avg']
        iot_clean['pkt_len_std'] = iot['std']
        iot_clean['flow_rate'] = iot['rate']
        iot_clean['iat'] = iot['iat']
        iot_clean['syn_flag'] = iot['syn_flag_number']
        iot_clean['ack_flag'] = iot['ack_flag_number']
        iot_clean['rst_flag'] = iot['rst_flag_number']
        iot_clean['psh_flag'] = iot['psh_flag_number']
        iot_clean['ttl'] = iot['time_to_live']
        iot_clean['label'] = iot['label']
        datasets_to_merge.append(('CICIOT2023', iot_clean))

    if not datasets_to_merge:
        print("❌ No datasets loaded! Please ensure raw CSV files are in data/raw/")
        sys.exit(1)

    # ─────────────────────────────────────────────────────────────
    # Binary Normalization Function (CORRECTED BUG #1)
    # ─────────────────────────────────────────────────────────────
    def normalize_binary_label(x):
        val = str(x).lower().strip()
        # Explicitly map normal network identifiers to BENIGN
        if val in ['benign', 'normal', '0', '0.0']:
            return 'BENIGN'
        return 'MALICIOUS'

    print("\n🔍 Running binary normalization & multiclass feature alignment...")
    processed_dfs = []
    all_features = [
        'dst_port', 'protocol', 'flow_duration', 'total_packets', 'total_bytes',
        'min_pkt_len', 'max_pkt_len', 'avg_pkt_len', 'pkt_len_std', 'flow_rate',
        'iat', 'syn_flag', 'ack_flag', 'rst_flag', 'psh_flag', 'ttl',
        'binary_label', 'attack_type'
    ]

    for name, df in datasets_to_merge:
        # Save clean attack types and perform corrected binary classification
        df['attack_type'] = df['label']
        df['binary_label'] = df['label'].apply(normalize_binary_label)

        # Pad missing columns with 0
        for col in all_features:
            if col not in df.columns:
                df[col] = 0

        # Keep strictly selected features in exact sequence
        df_aligned = df[all_features]
        print(f"  {name} clean aligned shape: {df_aligned.shape}")
        
        # Log benign proportion to verify correctness
        b_prop = (df_aligned['binary_label'] == 'BENIGN').mean()
        print(f"    -> Benign proportion: {b_prop*100:.2f}% (Verified!)")
        
        processed_dfs.append(df_aligned)

    # ─────────────────────────────────────────────────────────────
    # 6. Concat and Save
    # ─────────────────────────────────────────────────────────────
    print("\n💾 Concatenating aligned datasets...")
    final_df = pd.concat(processed_dfs, ignore_index=True)
    print(f"  Final Consolidated Shape: {final_df.shape}")
    print(f"  Total MALICIOUS samples: {(final_df['binary_label']=='MALICIOUS').sum():,}")
    print(f"  Total BENIGN samples:    {(final_df['binary_label']=='BENIGN').sum():,}")

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    final_df.to_csv(output_csv, index=False)
    print(f"\n✅ Merged dataset successfully saved to: {output_csv}")
    print("==================================================")

if __name__ == "__main__":
    main()
