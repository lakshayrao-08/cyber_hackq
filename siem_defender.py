import os
import sys
import time
import json
import socket
import threading
import psutil
from datetime import datetime
from queue import Queue

# ==========================================
# ENTERPRISE SECURITY RULES ENGINE (STATIC THREAT INTEL)
# ==========================================
KNOWN_SUSPICIOUS_PROCESSES = ["nc", "ncat", "nmap", "wireshark", "hydra", "john", "mimikatz"]
SENSITIVE_DIRECTORIES = ["/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\drivers\\etc\\hosts"]

class SecurityThreatIntel:
    @staticmethod
    def calculate_risk_score(cpu_percent, memory_percent, process_name, open_files):
        """
        Anomalous Activity Risk Matrix Evaluation Formula:
        Risk = (w1 * CPU) + (w2 * MEM) + IdentityHeuristics + ContextualFlags
        """
        score = 0.0
        # Metric weightings
        score += (cpu_percent * 0.2) + (memory_percent * 0.2)
        
        # Identity Checks
        if process_name.lower() in KNOWN_SUSPICIOUS_PROCESSES:
            score += 50.0
            
        # Privilege/Access Checks
        for f in open_files:
            if any(target in f for target in SENSITIVE_DIRECTORIES):
                score += 40.0
                
        return min(100.0, score)

# ==========================================
# ASYNCHRONOUS SECURITY TELEMETRY PIPELINE
# ==========================================
class SecuritySIEMEngine:
    def __init__(self):
        self.event_queue = Queue()
        self.is_monitoring = False
        self.system_identity = f"{socket.gethostname()} | {socket.gethostbyname(socket.gethostname())}"
        self.alerts_log = []

    def start_ingestion_pipelines(self):
        self.is_monitoring = True
        
        # Spin up concurrent worker threads for isolation
        threading.Thread(target=self._process_telemetry_sensor, daemon=True).start()
        threading.Thread(target=self._network_telemetry_sensor, daemon=True).start()
        threading.Thread(target=self._analysis_correlation_engine, daemon=True).start()

    def _process_telemetry_sensor(self):
        """Continuously snapshots system operational execution profiles"""
        while self.is_monitoring:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    p_info = proc.info
                    open_files = [f.path for f in proc.open_files()] if hasattr(proc, 'open_files') else []
                    
                    risk = SecurityThreatIntel.calculate_risk_score(
                        p_info['cpu_percent'] or 0,
                        p_info['memory_percent'] or 0,
                        p_info['name'] or "",
                        open_files
                    )
                    
                    if risk > 45.0:  # High Threat Alert Threshold
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "subsystem": "PROCESS_MONITOR",
                            "severity": "HIGH" if risk > 75.0 else "MEDIUM",
                            "entity_id": p_info['pid'],
                            "entity_name": p_info['name'],
                            "risk_score": round(risk, 2),
                            "details": f"Process displaying abnormal telemetry patterns. Memory Consumption: {p_info['memory_percent']}%"
                        }
                        self.event_queue.put(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            time.sleep(3)

    def _network_telemetry_sensor(self):
        """Monitors network socket bindings for persistent egress communication tunnels"""
        while self.is_monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'LISTEN' and conn.laddr.port in [21, 22, 23, 445]:
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "subsystem": "NETWORK_SENSOR",
                            "severity": "CRITICAL" if conn.laddr.port == 23 else "LOW",
                            "entity_id": conn.pid,
                            "entity_name": f"Port Binding {conn.laddr.port}",
                            "risk_score": 85.0 if conn.laddr.port == 23 else 30.0,
                            "details": f"Inbound network service listening on high-risk protocol port: {conn.laddr.port}"
                        }
                        self.event_queue.put(event)
            except Exception:
                pass
            time.sleep(5)

    def _analysis_correlation_engine(self):
        """Correlates logs from distinct processing chains to confirm incidents"""
        while self.is_monitoring:
            if not self.event_queue.empty():
                raw_event = self.event_queue.get()
                
                # Dynamic Threat Verification Layer
                if raw_event["risk_score"] >= 50.0:
                    raw_event["mitigation_state"] = "TRIGGERED_ADMIN_ALERT"
                    self.alerts_log.insert(0, raw_event)  # Prepend newest events
                
                self.event_queue.task_done()
            time.sleep(0.1)

    def generate_live_dashboard_data(self):
        """Structures operational state arrays for UI consumption"""
        cpu_total = psutil.cpu_percent()
        ram_total = psutil.virtual_memory().percent
        
        return {
            "node_identity": self.system_identity,
            "engine_status": "ACTIVE_PROTECTION",
            "global_metrics": {"cpu_utilization": cpu_total, "memory_utilization": ram_total},
            "active_alerts": self.alerts_log[:15],  # Return up to 15 latest alerts
            "total_alerts_captured": len(self.alerts_log)
        }

# Global initialization framework instantiation
siem_system = SecuritySIEMEngine()
siem_system.start_ingestion_pipelines()