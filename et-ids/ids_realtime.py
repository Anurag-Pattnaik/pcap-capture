from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import statistics
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ids_storage import IDSStorage


LOGGER = logging.getLogger(__name__)

ENCRYPTED_PORTS = {443, 465, 563, 853, 993, 995, 8443}
ROLLING_WINDOW_SIZE = 50
DEFAULT_LOG_LIMIT = 500
HIGH_PACKET_RATE_THRESHOLD = 1000.0
MIN_FLOW_PACKETS_FOR_ML = 8
MIN_FLOW_DURATION_FOR_ML = 2.0
ML_ATTACK_ALERT_THRESHOLD = 80.0
BENIGN_LABELS = {"benign", "normal"}
CRITICAL_LABEL_KEYWORDS = {"ddos", "dos", "botnet", "infiltration", "ransomware"}
HIGH_LABEL_KEYWORDS = {"brute", "exploit", "web attack", "sql", "xss", "portscan", "scan"}
MEDIUM_LABEL_KEYWORDS = {"suspicious", "attack", "malware", "anomaly"}


@dataclass(frozen=True)
class PacketLog:
    id: int
    timestamp: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    flow_id: str
    flow_packet_count: int
    flow_byte_count: int
    flow_duration: float
    length: int
    time_diff: float
    packet_rate: float
    avg_length: float
    encrypted_likely: bool
    prediction: str
    ml_confidence: float | None
    binary_label: str | None
    attack_label: str | None
    severity: str
    signature: str
    rule_id: str
    action: str
    reason: str


class BlockManager:
    def __init__(
        self,
        mode: str = "memory",
        blocked_ips: list[str] | None = None,
        on_block: Callable[[str, str], None] | None = None,
        on_unblock: Callable[[str], None] | None = None,
    ) -> None:
        self.mode = mode.strip().lower()
        self._blocked_ips: set[str] = set(blocked_ips or [])
        self._on_block = on_block
        self._on_unblock = on_unblock
        self._lock = threading.Lock()

    def list_blocked(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    def is_blocked(self, ip_address_value: str | None) -> bool:
        if not ip_address_value:
            return False

        with self._lock:
            return ip_address_value in self._blocked_ips

    def block(self, ip_address_value: str, reason: str = "Manual block from IDS log") -> dict[str, str]:
        normalized_ip = self._validate_ip(ip_address_value)

        with self._lock:
            self._blocked_ips.add(normalized_ip)

        if self.mode == "windows_firewall":
            self._apply_windows_firewall_block(normalized_ip)
            action = "firewall_blocked"
        else:
            action = "memory_blocked"

        if self._on_block is not None:
            self._on_block(normalized_ip, reason)

        LOGGER.warning("Blocked IP %s: %s", normalized_ip, reason)
        return {"ip": normalized_ip, "action": action, "reason": reason}

    def unblock(self, ip_address_value: str) -> dict[str, str]:
        normalized_ip = self._validate_ip(ip_address_value)

        with self._lock:
            self._blocked_ips.discard(normalized_ip)

        if self.mode == "windows_firewall":
            self._remove_windows_firewall_block(normalized_ip)
            action = "firewall_unblocked"
        else:
            action = "memory_unblocked"

        if self._on_unblock is not None:
            self._on_unblock(normalized_ip)

        LOGGER.info("Unblocked IP %s", normalized_ip)
        return {"ip": normalized_ip, "action": action}

    @staticmethod
    def _validate_ip(ip_address_value: str) -> str:
        try:
            return str(ipaddress.ip_address(ip_address_value))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip_address_value}") from exc

    @staticmethod
    def _apply_windows_firewall_block(ip_address_value: str) -> None:
        rule_name = f"ET-IDS Block {ip_address_value}"
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address_value}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _remove_windows_firewall_block(ip_address_value: str) -> None:
        rule_name = f"ET-IDS Block {ip_address_value}"
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )


class RealtimeIDS:
    def __init__(
        self,
        *,
        detector: Any | None = None,
        block_manager: BlockManager | None = None,
        storage: IDSStorage | None = None,
        log_limit: int = DEFAULT_LOG_LIMIT,
    ) -> None:
        self.detector = detector
        self.block_manager = block_manager or BlockManager()
        self.storage = storage
        self.logs: deque[PacketLog] = deque(maxlen=log_limit)
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._subscribers_lock = threading.Lock()
        self._recent_lengths: deque[int] = deque(maxlen=ROLLING_WINDOW_SIZE)
        self._recent_timestamps: deque[float] = deque(maxlen=ROLLING_WINDOW_SIZE)
        self._flows: dict[tuple[str | None, str | None, int | str | None], dict[str, Any]] = {}
        self._previous_timestamp: float | None = None
        self._packet_counter = 0
        self._sniffer: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._interface: str | None = None
        self._filter: str | None = None
        self._load_persisted_logs()

    @property
    def is_running(self) -> bool:
        return bool(self._sniffer and getattr(self._sniffer, "running", False))

    def set_detector(self, detector: Any | None) -> None:
        self.detector = detector

    @staticmethod
    def list_interfaces() -> list[str]:
        try:
            from scapy.all import get_if_list
        except ImportError as exc:
            raise RuntimeError("Scapy is required to list capture interfaces.") from exc

        return sorted(get_if_list())

    async def start_capture(self, interface: str | None = None, packet_filter: str | None = None) -> dict[str, Any]:
        if self.is_running:
            return self.status()

        try:
            from scapy.all import AsyncSniffer
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live packet capture.") from exc

        self._loop = asyncio.get_running_loop()
        self._interface = interface or None
        self._filter = packet_filter or None
        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=self._filter,
            prn=self._handle_packet,
            store=False,
        )
        self._sniffer.start()
        LOGGER.info("Started live capture interface=%s filter=%s", self._interface, self._filter)
        return self.status()

    async def stop_capture(self) -> dict[str, Any]:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                LOGGER.exception("Failed to stop packet capture cleanly")
            finally:
                self._sniffer = None

        LOGGER.info("Stopped live capture")
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.is_running,
            "interface": self._interface,
            "filter": self._filter,
            "log_count": len(self.logs),
            "flow_count": len(self._flows),
            "ml_min_packets": MIN_FLOW_PACKETS_FOR_ML,
            "ml_min_duration": MIN_FLOW_DURATION_FOR_ML,
            "ml_attack_threshold": ML_ATTACK_ALERT_THRESHOLD,
            "blocked_ips": self.block_manager.list_blocked(),
        }

    def recent_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, self.logs.maxlen or DEFAULT_LOG_LIMIT))
        return [asdict(log) for log in list(self.logs)[-bounded_limit:]]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._subscribers_lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._subscribers_lock:
            self._subscribers.discard(queue)

    def block_ip(self, ip_address_value: str, reason: str = "Manual block from IDS log") -> dict[str, str]:
        result = self.block_manager.block(ip_address_value, reason)
        self._publish({"type": "blocklist", "data": self.status()})
        return result

    def unblock_ip(self, ip_address_value: str) -> dict[str, str]:
        result = self.block_manager.unblock(ip_address_value)
        self._publish({"type": "blocklist", "data": self.status()})
        return result

    def analyze_pcap(self, pcap_file: str | Path, packet_limit: int = 5000) -> dict[str, Any]:
        try:
            from scapy.all import PcapReader
        except ImportError as exc:
            raise RuntimeError("Scapy is required to analyze PCAP files.") from exc

        resolved_path = Path(pcap_file).expanduser().resolve()
        if not resolved_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {resolved_path}")

        processed_packets = 0
        alert_count = 0
        bounded_limit = max(1, min(packet_limit, 50000))

        with PcapReader(str(resolved_path)) as reader:
            for packet in reader:
                if processed_packets >= bounded_limit:
                    break

                packet_log = self.process_packet(packet)
                processed_packets += 1
                if packet_log.severity in {"critical", "high", "medium", "low"} or packet_log.action in {"alert", "blocked"}:
                    alert_count += 1

        return {
            "processed_packets": processed_packets,
            "alert_count": alert_count,
            "packet_limit": bounded_limit,
            "logs": self.recent_logs(100),
        }

    def process_packet(self, packet: Any) -> PacketLog:
        packet_log = self._build_packet_log(packet)
        self.logs.append(packet_log)
        packet_log_data = asdict(packet_log)
        if self.storage is not None:
            self.storage.save_packet_log(packet_log_data)
        self._publish({"type": "packet_log", "data": packet_log_data})
        return packet_log

    def _handle_packet(self, packet: Any) -> None:
        try:
            self.process_packet(packet)
        except Exception:
            LOGGER.exception("Failed to process captured packet")

    def _build_packet_log(self, packet: Any) -> PacketLog:
        timestamp = float(getattr(packet, "time", datetime.now(timezone.utc).timestamp()))
        time_diff = 0.0 if self._previous_timestamp is None else max(timestamp - self._previous_timestamp, 0.0)
        packet_length = int(len(packet))

        self._previous_timestamp = timestamp
        self._recent_lengths.append(packet_length)
        self._recent_timestamps.append(timestamp)
        packet_rate = self._rolling_packet_rate()
        avg_length = sum(self._recent_lengths) / len(self._recent_lengths)
        self._packet_counter += 1

        metadata = self._extract_metadata(packet)
        detection_features = self._build_detection_features(metadata, packet_length, time_diff, packet_rate, avg_length, timestamp)
        encrypted_likely = self._is_encrypted_likely(metadata)
        decision = self._predict(detection_features, encrypted_likely)
        severity, signature, rule_id = self._classify_detection(
            decision["prediction"],
            decision["reason"],
            decision["ml_confidence"],
        )
        action = self._select_action(metadata, decision["prediction"])

        return PacketLog(
            id=self._packet_counter,
            timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            source_ip=metadata["source_ip"],
            destination_ip=metadata["destination_ip"],
            source_port=metadata["source_port"],
            destination_port=metadata["destination_port"],
            protocol=metadata["protocol"],
            flow_id=str(detection_features["flow_id"]),
            flow_packet_count=int(detection_features["total_packets"]),
            flow_byte_count=int(detection_features["total_bytes"]),
            flow_duration=round(float(detection_features["flow_duration"]), 3),
            length=packet_length,
            time_diff=round(time_diff, 6),
            packet_rate=round(packet_rate, 3),
            avg_length=round(avg_length, 3),
            encrypted_likely=encrypted_likely,
            prediction=decision["prediction"],
            ml_confidence=decision["ml_confidence"],
            binary_label=decision["binary_label"],
            attack_label=decision["attack_label"],
            severity=severity,
            signature=signature,
            rule_id=rule_id,
            action=action,
            reason=decision["reason"],
        )

    def _extract_metadata(self, packet: Any) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": packet.lastlayer().name if hasattr(packet, "lastlayer") else "UNKNOWN",
            "protocol_number": 0,
            "ttl": 0,
            "syn_flag": 0,
            "ack_flag": 0,
            "rst_flag": 0,
            "psh_flag": 0,
        }

        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
        except ImportError:
            return metadata

        if packet.haslayer(IP):
            metadata["source_ip"] = packet[IP].src
            metadata["destination_ip"] = packet[IP].dst
            metadata["protocol"] = "IP"
            metadata["protocol_number"] = int(packet[IP].proto)
            metadata["ttl"] = int(packet[IP].ttl)
        elif packet.haslayer(IPv6):
            metadata["source_ip"] = packet[IPv6].src
            metadata["destination_ip"] = packet[IPv6].dst
            metadata["protocol"] = "IPv6"
            metadata["protocol_number"] = int(packet[IPv6].nh)
            metadata["ttl"] = int(packet[IPv6].hlim)

        if packet.haslayer(TCP):
            metadata["source_port"] = int(packet[TCP].sport)
            metadata["destination_port"] = int(packet[TCP].dport)
            metadata["protocol"] = "TCP"
            flags = int(packet[TCP].flags)
            metadata["syn_flag"] = int(bool(flags & 0x02))
            metadata["ack_flag"] = int(bool(flags & 0x10))
            metadata["rst_flag"] = int(bool(flags & 0x04))
            metadata["psh_flag"] = int(bool(flags & 0x08))
        elif packet.haslayer(UDP):
            metadata["source_port"] = int(packet[UDP].sport)
            metadata["destination_port"] = int(packet[UDP].dport)
            metadata["protocol"] = "UDP"
        elif packet.haslayer(ICMP):
            metadata["protocol"] = "ICMP"

        return metadata

    def _is_encrypted_likely(self, metadata: Mapping[str, Any]) -> bool:
        ports = {metadata.get("source_port"), metadata.get("destination_port")}
        return bool(ENCRYPTED_PORTS.intersection(port for port in ports if port is not None))

    def _build_detection_features(
        self,
        metadata: Mapping[str, Any],
        length: int,
        time_diff: float,
        packet_rate: float,
        avg_length: float,
        observed_at: float | None = None,
    ) -> dict[str, float | int | str]:
        now = observed_at if observed_at is not None else datetime.now(timezone.utc).timestamp()
        flow_key = (
            metadata.get("source_ip"),
            metadata.get("destination_ip"),
            metadata.get("protocol_number") or metadata.get("protocol"),
        )
        flow_id = self._stable_rule_suffix("|".join(str(part) for part in flow_key))
        flow = self._flows.setdefault(
            flow_key,
            {
                "start_time": now,
                "last_seen": now,
                "total_packets": 0,
                "total_bytes": 0,
                "lengths": deque(maxlen=ROLLING_WINDOW_SIZE),
            },
        )
        flow["total_packets"] += 1
        flow["total_bytes"] += length
        flow["last_seen"] = now
        flow["lengths"].append(length)

        flow_duration = max(now - float(flow["start_time"]), 0.000001)
        lengths = list(flow["lengths"])
        min_pkt_len = min(lengths) if lengths else length
        max_pkt_len = max(lengths) if lengths else length
        avg_pkt_len = sum(lengths) / len(lengths) if lengths else avg_length
        pkt_len_std = statistics.pstdev(lengths) if len(lengths) > 1 else 0.0
        total_packets = int(flow["total_packets"])
        total_bytes = int(flow["total_bytes"])
        bytes_per_packet = total_bytes / (total_packets + 0.000001)
        packets_per_second = total_packets / (flow_duration + 0.000001)
        byte_rate = total_bytes / (flow_duration + 0.000001)
        burstiness = pkt_len_std / (avg_pkt_len + 0.000001)
        flag_sum = (
            int(metadata.get("syn_flag") or 0)
            + int(metadata.get("ack_flag") or 0)
            + int(metadata.get("rst_flag") or 0)
            + int(metadata.get("psh_flag") or 0)
        )

        return {
            "flow_id": flow_id,
            "dst_port": int(metadata.get("destination_port") or 0),
            "protocol": int(metadata.get("protocol_number") or 0),
            "flow_duration": flow_duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "min_pkt_len": min_pkt_len,
            "max_pkt_len": max_pkt_len,
            "avg_pkt_len": avg_pkt_len,
            "pkt_len_std": pkt_len_std,
            "flow_rate": byte_rate,
            "iat": time_diff,
            "syn_flag": int(metadata.get("syn_flag") or 0),
            "ack_flag": int(metadata.get("ack_flag") or 0),
            "rst_flag": int(metadata.get("rst_flag") or 0),
            "psh_flag": int(metadata.get("psh_flag") or 0),
            "ttl": int(metadata.get("ttl") or 0),
            "bytes_per_packet": bytes_per_packet,
            "packets_per_second": packets_per_second,
            "avg_packet_size": bytes_per_packet,
            "byte_rate": byte_rate,
            "burstiness": burstiness,
            "flag_sum": flag_sum,
            "length": length,
            "time_diff": time_diff,
            "packet_rate": packet_rate,
            "avg_length": avg_length,
        }

    def _predict(
        self,
        features: Mapping[str, Any],
        encrypted_likely: bool,
    ) -> dict[str, Any]:
        if not self._is_flow_ready_for_ml(features):
            return self._decision(
                prediction="Normal",
                reason="flow_warmup",
                signature_label=None,
            )

        if self.detector is not None:
            expected_features = self.detector.expected_features()
            if expected_features is None or set(expected_features).issubset(features):
                if hasattr(self.detector, "predict_details"):
                    result = self.detector.predict_details(features)
                    confidence = result.confidence
                    prediction = result.prediction
                    normalized_prediction = prediction.strip().lower()
                    if normalized_prediction not in BENIGN_LABELS and confidence is not None:
                        if confidence < ML_ATTACK_ALERT_THRESHOLD:
                            return self._decision(
                                prediction="Normal",
                                reason="model_low_confidence",
                                ml_confidence=confidence,
                                binary_label=result.binary_label,
                                attack_label=result.attack_label,
                            )

                    return self._decision(
                        prediction=prediction,
                        reason="model_prediction",
                        ml_confidence=confidence,
                        binary_label=result.binary_label,
                        attack_label=result.attack_label,
                    )

                return self._decision(
                    prediction=self.detector.predict(features),
                    reason="model_prediction",
                )

        if float(features.get("packet_rate") or 0.0) > HIGH_PACKET_RATE_THRESHOLD:
            return self._decision(prediction="Suspicious", reason="high_packet_rate")
        if encrypted_likely:
            return self._decision(prediction="Normal", reason="encrypted_metadata_only")
        return self._decision(prediction="Normal", reason="metadata_baseline")

    @staticmethod
    def _is_flow_ready_for_ml(features: Mapping[str, Any]) -> bool:
        total_packets = int(features.get("total_packets") or 0)
        flow_duration = float(features.get("flow_duration") or 0.0)
        return total_packets >= MIN_FLOW_PACKETS_FOR_ML and flow_duration >= MIN_FLOW_DURATION_FOR_ML

    @staticmethod
    def _decision(
        *,
        prediction: str,
        reason: str,
        signature_label: str | None = None,
        ml_confidence: float | None = None,
        binary_label: str | None = None,
        attack_label: str | None = None,
    ) -> dict[str, Any]:
        return {
            "prediction": prediction,
            "reason": reason,
            "signature_label": signature_label,
            "ml_confidence": ml_confidence,
            "binary_label": binary_label,
            "attack_label": attack_label,
        }

    def _rolling_packet_rate(self) -> float:
        if len(self._recent_timestamps) < 2:
            return 0.0

        elapsed = self._recent_timestamps[-1] - self._recent_timestamps[0]
        if elapsed <= 0:
            return 0.0

        return (len(self._recent_timestamps) - 1) / elapsed

    def _classify_detection(
        self,
        prediction: str,
        reason: str,
        ml_confidence: float | None = None,
    ) -> tuple[str, str, str]:
        label = prediction.strip()
        normalized_label = label.lower()

        if reason == "model_prediction":
            return (
                self._severity_from_model_label(normalized_label, ml_confidence),
                f"ML classification: {label}",
                f"ML-{self._stable_rule_suffix(normalized_label)}",
            )

        if reason == "model_low_confidence":
            return "info", "ML monitoring: low confidence", "ML-MONITOR"

        if reason == "flow_warmup":
            return "info", "Flow warmup: collecting evidence", "FLOW-WARMUP"

        if reason == "high_packet_rate":
            return "critical", "Sustained packet-rate anomaly", "META-1001"

        if reason == "encrypted_metadata_only":
            return "info", "Encrypted service metadata", "META-1002"

        return "info", "Metadata baseline", "META-0000"

    @staticmethod
    def _severity_from_model_label(normalized_label: str, confidence: float | None = None) -> str:
        if normalized_label in BENIGN_LABELS:
            return "info"
        if confidence is not None and confidence < ML_ATTACK_ALERT_THRESHOLD:
            return "info"
        if confidence is not None and confidence < 90.0:
            return "medium"
        if any(keyword in normalized_label for keyword in CRITICAL_LABEL_KEYWORDS):
            return "critical"
        if any(keyword in normalized_label for keyword in HIGH_LABEL_KEYWORDS):
            return "high"
        if any(keyword in normalized_label for keyword in MEDIUM_LABEL_KEYWORDS):
            return "medium"
        return "medium"

    @staticmethod
    def _stable_rule_suffix(value: str) -> str:
        import hashlib

        digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
        return digest[:8].upper()

    def _select_action(self, metadata: Mapping[str, Any], prediction: str) -> str:
        source_ip = metadata.get("source_ip")
        destination_ip = metadata.get("destination_ip")
        if self.block_manager.is_blocked(source_ip) or self.block_manager.is_blocked(destination_ip):
            return "blocked"
        if prediction.strip().lower() not in {"normal", "benign"}:
            return "alert"
        return "allow"

    def _publish(self, event: dict[str, Any]) -> None:
        with self._subscribers_lock:
            subscribers = list(self._subscribers)

        if not subscribers or self._loop is None:
            return

        for queue in subscribers:
            self._loop.call_soon_threadsafe(self._enqueue_event, queue, event)

    @staticmethod
    def _enqueue_event(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(event)
            except asyncio.QueueEmpty:
                pass

    def _load_persisted_logs(self) -> None:
        if self.storage is None:
            return

        for log_data in self.storage.recent_logs(self.logs.maxlen or DEFAULT_LOG_LIMIT):
            log_data.setdefault("flow_id", "LEGACY")
            log_data.setdefault("flow_packet_count", 0)
            log_data.setdefault("flow_byte_count", 0)
            log_data.setdefault("flow_duration", 0.0)
            log_data.setdefault("ml_confidence", None)
            log_data.setdefault("binary_label", None)
            log_data.setdefault("attack_label", None)
            log_data.setdefault("severity", self._severity_from_model_label(str(log_data.get("prediction", "")).lower()))
            log_data.setdefault("signature", str(log_data.get("prediction") or "Metadata baseline"))
            log_data.setdefault("rule_id", "LEGACY-0000")
            packet_log = PacketLog(**log_data)
            self.logs.append(packet_log)
            self._packet_counter = max(self._packet_counter, packet_log.id)


def export_logs_to_csv(logs: list[dict[str, Any]], output_path: str | Path) -> Path:
    import pandas as pd

    resolved_path = Path(output_path).expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(logs).to_csv(resolved_path, index=False)
    return resolved_path
