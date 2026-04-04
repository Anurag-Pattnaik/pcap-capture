from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import ICMP, IP, TCP, UDP


LOGGER = logging.getLogger(__name__)
ROLLING_WINDOW_SIZE = 10


def _detect_protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IP):
        return "IP"
    return packet.lastlayer().name if hasattr(packet, "lastlayer") else "UNKNOWN"


def _build_feature_row(
    *,
    timestamp: float,
    packet_length: int,
    protocol: str,
    previous_timestamp: float | None,
    packet_index: int,
    rolling_average_length: float,
) -> dict[str, float | int | str]:
    inter_arrival_time = 0.0 if previous_timestamp is None else max(timestamp - previous_timestamp, 0.0)
    packet_rate = 0.0 if inter_arrival_time <= 0 else 1.0 / inter_arrival_time

    return {
        "packet_length": packet_length,
        "protocol": protocol,
        "timestamp": timestamp,
        "inter_arrival_time": inter_arrival_time,
        "packet_rate": packet_rate,
        "rolling_avg_packet_length": rolling_average_length,
        "packet_index": packet_index,
    }


def extract_features(pcap_file: str | Path) -> pd.DataFrame:
    """
    Read a PCAP file and extract packet-level metadata features.

    Parameters
    ----------
    pcap_file:
        Path to the PCAP file to process.

    Returns
    -------
    pandas.DataFrame
        Packet metadata features suitable for intrusion detection workflows.
    """
    pcap_path = Path(pcap_file).expanduser().resolve()
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    rows: list[dict[str, float | int | str]] = []
    previous_timestamp: float | None = None
    recent_lengths: list[int] = []

    LOGGER.info("Extracting features from %s", pcap_path)

    with PcapReader(str(pcap_path)) as reader:
        for packet_index, packet in enumerate(reader):
            timestamp = float(packet.time)
            packet_length = int(len(packet))
            protocol = _detect_protocol(packet)

            recent_lengths.append(packet_length)
            if len(recent_lengths) > ROLLING_WINDOW_SIZE:
                recent_lengths.pop(0)

            rolling_average_length = sum(recent_lengths) / len(recent_lengths)
            row = _build_feature_row(
                timestamp=timestamp,
                packet_length=packet_length,
                protocol=protocol,
                previous_timestamp=previous_timestamp,
                packet_index=packet_index,
                rolling_average_length=rolling_average_length,
            )
            rows.append(row)
            previous_timestamp = timestamp

    dataframe = pd.DataFrame(
        rows,
        columns=[
            "packet_length",
            "protocol",
            "timestamp",
            "inter_arrival_time",
            "packet_rate",
            "rolling_avg_packet_length",
            "packet_index",
        ],
    )

    return dataframe


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract metadata-only intrusion detection features from a PCAP file."
    )
    parser.add_argument("pcap_file", help="Path to the input PCAP file.")
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output CSV file. Defaults to the PCAP filename with a .csv suffix.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    pcap_path = Path(args.pcap_file).expanduser().resolve()
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else pcap_path.with_suffix(".csv")
    )

    dataframe = extract_features(pcap_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_csv(output_path, index=False)

    LOGGER.info("Saved %s rows to %s", len(dataframe), output_path)


if __name__ == "__main__":
    main()
