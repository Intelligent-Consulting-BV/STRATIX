"""
stratix.mappers
===============
Vendor-specific mappers: ECS, CIM, ASIM, Modbus, DNP3, OPC-UA → STRATIX

© 2026 Intelligent Consulting BV. All rights reserved.
Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
Licence: Apache 2.0 (implementation use only)
First published: 26 February 2026
"""

from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _map_technique(tags: list) -> Optional[str]:
    pattern = re.compile(r"T\d{4}(\.\d{3})?")
    for tag in tags:
        m = pattern.search(str(tag))
        if m:
            return m.group(0)
    return None


class ECSToStratix:
    """Elastic Common Schema → STRATIX"""
    CATEGORY_MAP = {
        "authentication": "credential_access", "file": "collection",
        "network": "command_and_control", "process": "execution",
        "registry": "persistence", "session": "lateral_movement",
        "malware": "execution", "intrusion_detection": "initial_access",
        "configuration": "defence_evasion", "driver": "privilege_escalation",
        "host": "discovery", "iam": "privilege_escalation",
        "threat": "impact", "vulnerability": "initial_access",
        "web": "initial_access", "package": "persistence",
    }

    def map(self, ecs_event: dict[str, Any]) -> dict[str, Any]:
        cats = ecs_event.get("event", {}).get("category", [])
        if isinstance(cats, str):
            cats = [cats]
        intent_cat = next((self.CATEGORY_MAP[c] for c in cats if c in self.CATEGORY_MAP), None)
        tags = ecs_event.get("tags", [])
        technique = _map_technique(tags)
        risk_score = ecs_event.get("event", {}).get("risk_score", 50)
        country = (ecs_event.get("observer", {}).get("geo", {}).get("country_iso_code") or
                   ecs_event.get("host", {}).get("geo", {}).get("country_iso_code"))
        stratix: dict = {
            "class_uid": 4001, "category_uid": 4,
            "time": ecs_event.get("@timestamp", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": "Elastic Security", "vendor": "Elastic NV",
                                     "version": ecs_event.get("agent", {}).get("version", "unknown")},
                         "source_schema": "ECS", "stratix_mapper_version": "1.0.0"},
            "sovereignty": {"source_schema": "ECS"},
        }
        if intent_cat:
            stratix["intent"] = {"category": intent_cat, "confidence_score": min(int(risk_score), 100)}
            if technique:
                stratix["intent"]["technique_id"] = technique
        if country:
            stratix["sovereignty"]["data_residency"] = country.upper()
        for f in ["host", "user", "process", "network", "file", "source", "destination"]:
            if f in ecs_event:
                stratix[f"ecs_{f}"] = ecs_event[f]
        stratix["raw"] = ecs_event
        return stratix

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


class CIMToStratix:
    """Splunk Common Information Model → STRATIX"""
    SOURCETYPE_MAP = {
        "authentication": "credential_access", "change": "defence_evasion",
        "change_analysis": "defence_evasion", "endpoint": "execution",
        "intrusion_detection": "initial_access", "malware": "execution",
        "network_sessions": "lateral_movement", "network_traffic": "command_and_control",
        "performance": "discovery", "vulnerabilities": "initial_access",
        "web": "initial_access", "alerts": "impact",
    }

    def map(self, cim_event: dict[str, Any]) -> dict[str, Any]:
        sourcetype = cim_event.get("sourcetype", "").lower()
        intent_cat = self.SOURCETYPE_MAP.get(sourcetype, "discovery")
        annotations = cim_event.get("annotations", {})
        technique = _map_technique(annotations.get("mitre_attack", []))
        stratix: dict = {
            "class_uid": 4001, "category_uid": 4,
            "time": cim_event.get("_time", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": "Splunk", "vendor": "Splunk Inc.", "version": "unknown"},
                         "source_schema": "Splunk-CIM", "stratix_mapper_version": "1.0.0"},
            "intent": {"category": intent_cat,
                       "confidence_score": int(cim_event.get("severity_id", 50))},
            "sovereignty": {"source_schema": "Splunk-CIM"},
        }
        if technique:
            stratix["intent"]["technique_id"] = technique
        for f in ["src", "dest", "user", "action", "signature", "severity"]:
            if f in cim_event:
                stratix[f"cim_{f}"] = cim_event[f]
        stratix["raw"] = cim_event
        return stratix

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


class ASIMToStratix:
    """Microsoft Sentinel ASIM → STRATIX"""
    SCHEMA_MAP = {
        "AuditEvent": "defence_evasion", "Authentication": "credential_access",
        "Dns": "command_and_control", "File": "collection",
        "NetworkSession": "lateral_movement", "Process": "execution",
        "RegistryEvent": "persistence", "UserManagement": "privilege_escalation",
        "WebSession": "initial_access",
    }
    SEVERITY_SCORE = {"Informational": 10, "Low": 30, "Medium": 55, "High": 75, "Critical": 95}

    def map(self, asim_event: dict[str, Any]) -> dict[str, Any]:
        schema = asim_event.get("EventSchema", "")
        intent_cat = self.SCHEMA_MAP.get(schema, "discovery")
        tags = asim_event.get("AdditionalFields", {}).get("Tactics", [])
        technique = _map_technique(tags if isinstance(tags, list) else [tags])
        resource_id = asim_event.get("_ResourceId", "")
        stratix: dict = {
            "class_uid": 4001, "category_uid": 4,
            "time": asim_event.get("TimeGenerated", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": asim_event.get("EventProduct", "Microsoft Sentinel"),
                                     "vendor": "Microsoft Corporation",
                                     "version": asim_event.get("EventSchemaVersion", "unknown")},
                         "source_schema": "ASIM", "stratix_mapper_version": "1.0.0"},
            "intent": {"category": intent_cat,
                       "confidence_score": self.SEVERITY_SCORE.get(
                           asim_event.get("EventSeverity", "Informational"), 50)},
            "sovereignty": {"source_schema": "ASIM"},
        }
        if technique:
            stratix["intent"]["technique_id"] = technique
        if "europe" in resource_id.lower() or "eu" in resource_id.lower():
            stratix["sovereignty"]["data_residency"] = "EU"
        for f in ["SrcIpAddr", "DstIpAddr", "ActorUsername", "EventResult"]:
            if f in asim_event:
                stratix[f"asim_{f}"] = asim_event[f]
        stratix["raw"] = asim_event
        return stratix

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


class ModbusToStratix:
    """Modbus TCP/RTU frames → STRATIX OT Layer"""
    FUNCTION_CODES = {
        0x01: "Read Coils", 0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers", 0x04: "Read Input Registers",
        0x05: "Write Single Coil", 0x06: "Write Single Register",
        0x0F: "Write Multiple Coils", 0x10: "Write Multiple Registers",
        0x16: "Mask Write Register", 0x17: "Read/Write Multiple Registers",
        0x2B: "Encapsulated Interface Transport",
    }
    WRITE_CODES = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}

    def map(self, frame: dict, asset_id: str = "unknown",
            purdue_level: int = 1, data_residency: str = "BE") -> dict:
        fn_code = frame.get("function_code", 0)
        is_write = fn_code in self.WRITE_CODES
        return {
            "class_uid": 5001, "category_uid": 5,
            "time": frame.get("timestamp", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": "Modbus Protocol Adapter",
                                     "vendor": "Intelligent Consulting BV", "version": "1.0.0"},
                         "source_schema": "Modbus", "stratix_mapper_version": "1.0.0"},
            "intent": {
                "category": "execution" if is_write else "discovery",
                "confidence_score": 75 if is_write else 20,
                "kill_chain_phase": "actions_on_objectives" if is_write else "reconnaissance",
            },
            "ot": {
                "event_class": "industrial_protocol_event", "asset_id": asset_id,
                "purdue_level": purdue_level, "protocol": "Modbus",
                "function_code": fn_code,
                "function_name": self.FUNCTION_CODES.get(fn_code, f"Unknown (0x{fn_code:02X})"),
                "is_write_operation": is_write,
                "unit_id": frame.get("unit_id"), "transaction_id": frame.get("transaction_id"),
                "data_address": frame.get("data_address"), "data_value": frame.get("data_value"),
                "src_ip": frame.get("src_ip"), "dst_ip": frame.get("dst_ip"),
                "src_port": frame.get("src_port"), "dst_port": frame.get("dst_port", 502),
            },
            "sovereignty": {"data_residency": data_residency, "classification": "restricted",
                            "nis2_category": "essential_entity", "source_schema": "Modbus"},
        }

    def map_batch(self, frames: list[dict], **kw) -> list[dict]:
        return [self.map(f, **kw) for f in frames]


class DNP3ToStratix:
    """DNP3 frames → STRATIX OT Layer"""
    FUNCTION_CODES = {
        0x00: "Confirm", 0x01: "Read", 0x02: "Write",
        0x03: "Select", 0x04: "Operate", 0x05: "Direct Operate",
        0x06: "Direct Operate NR", 0x07: "Immed Freeze",
        0x0D: "Cold Restart", 0x0E: "Warm Restart",
        0x14: "Authentication Request", 0x20: "Unsolicited Response",
        0x81: "Response", 0x82: "Unsolicited Response",
    }
    HIGH_RISK = {0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E}

    def map(self, frame: dict, asset_id: str = "unknown",
            purdue_level: int = 2, data_residency: str = "BE") -> dict:
        fn_code = frame.get("function_code", 0x01)
        is_high = fn_code in self.HIGH_RISK
        return {
            "class_uid": 5001, "category_uid": 5,
            "time": frame.get("timestamp", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": "DNP3 Protocol Adapter",
                                     "vendor": "Intelligent Consulting BV", "version": "1.0.0"},
                         "source_schema": "DNP3", "stratix_mapper_version": "1.0.0"},
            "intent": {
                "category": "impact" if is_high else "discovery",
                "confidence_score": 80 if is_high else 25,
                "kill_chain_phase": "actions_on_objectives" if is_high else "reconnaissance",
                "blast_radius": ["operational_technology", "critical_infrastructure"] if is_high else [],
            },
            "ot": {
                "event_class": "industrial_protocol_event", "asset_id": asset_id,
                "purdue_level": purdue_level, "protocol": "DNP3",
                "function_code": fn_code,
                "function_name": self.FUNCTION_CODES.get(fn_code, f"Unknown (0x{fn_code:02X})"),
                "is_high_risk": is_high,
                "master_address": frame.get("master_address"),
                "outstation_address": frame.get("outstation_address"),
                "src_ip": frame.get("src_ip"), "dst_ip": frame.get("dst_ip"),
            },
            "sovereignty": {"data_residency": data_residency, "classification": "sovereign",
                            "nis2_category": "essential_entity", "source_schema": "DNP3"},
        }

    def map_batch(self, frames: list[dict], **kw) -> list[dict]:
        return [self.map(f, **kw) for f in frames]


class OPCUAToStratix:
    """OPC-UA events → STRATIX OT Layer"""
    SERVICE_MAP = {
        "Read":                 ("discovery",        "reconnaissance",        20),
        "Write":                ("execution",         "actions_on_objectives", 75),
        "Browse":               ("discovery",        "reconnaissance",        15),
        "Call":                 ("execution",         "exploitation",          65),
        "CreateSession":        ("lateral_movement", "installation",          50),
        "ActivateSession":      ("lateral_movement", "installation",          55),
        "CloseSession":         ("defence_evasion",  "installation",          30),
        "CreateSubscription":   ("collection",        "actions_on_objectives", 60),
        "DeleteSubscription":   ("defence_evasion",  "installation",          35),
        "Publish":              ("collection",        "actions_on_objectives", 40),
        "AddNodes":             ("persistence",       "installation",          70),
        "DeleteNodes":          ("defence_evasion",  "actions_on_objectives", 75),
        "TransferSubscriptions":("lateral_movement", "actions_on_objectives", 65),
    }

    def map(self, event: dict, asset_id: str = "unknown",
            purdue_level: int = 3, data_residency: str = "BE") -> dict:
        service = event.get("service_type", "Read")
        cat, phase, score = self.SERVICE_MAP.get(service, ("discovery", "reconnaissance", 20))
        return {
            "class_uid": 5001, "category_uid": 5,
            "time": event.get("timestamp", _now_iso()),
            "metadata": {"version": "1.3.0",
                         "product": {"name": "OPC-UA Protocol Adapter",
                                     "vendor": "Intelligent Consulting BV", "version": "1.0.0"},
                         "source_schema": "OPC-UA", "stratix_mapper_version": "1.0.0"},
            "intent": {"category": cat, "confidence_score": score, "kill_chain_phase": phase},
            "ot": {
                "event_class": "industrial_protocol_event", "asset_id": asset_id,
                "purdue_level": purdue_level, "protocol": "OPC-UA",
                "service_type": service, "session_id": event.get("session_id"),
                "node_id": event.get("node_id"), "endpoint_url": event.get("endpoint_url"),
                "security_mode": event.get("security_mode"),
                "client_ip": event.get("client_ip"), "user_identity": event.get("user_identity"),
                "status_code": event.get("status_code"),
            },
            "sovereignty": {"data_residency": data_residency, "classification": "restricted",
                            "nis2_category": "essential_entity", "source_schema": "OPC-UA"},
        }

    def map_batch(self, events: list[dict], **kw) -> list[dict]:
        return [self.map(e, **kw) for e in events]


MAPPER_REGISTRY: dict[str, Any] = {
    "ecs": ECSToStratix, "cim": CIMToStratix, "asim": ASIMToStratix,
    "modbus": ModbusToStratix, "dnp3": DNP3ToStratix, "opc-ua": OPCUAToStratix,
}

def get_mapper(source_schema: str):
    key = source_schema.lower()
    if key not in MAPPER_REGISTRY:
        raise ValueError(f"No STRATIX mapper for '{source_schema}'. Available: {list(MAPPER_REGISTRY)}")
    return MAPPER_REGISTRY[key]()
