#!/usr/bin/env python3
"""
stratix_mappers.py
==================
Vendor-specific mappers converting proprietary security schemas
to STRATIX-normalised events.

Supported mappers:
  - ECS-to-STRATIX      (Elastic Common Schema)
  - CIM-to-STRATIX      (Splunk Common Information Model)
  - ASIM-to-STRATIX     (Microsoft Sentinel ASIM)
  - Modbus-to-STRATIX   (OT industrial protocol)
  - DNP3-to-STRATIX     (OT industrial protocol)
  - OPC-UA-to-STRATIX   (OT industrial protocol)

© 2026 Intelligent Consulting BV. All rights reserved.
Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
First published: 26 February 2026
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional
import uuid


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _map_technique(tags: list) -> Optional[str]:
    """Extract first ATT&CK technique ID from a tag list."""
    import re
    pattern = re.compile(r"T\d{4}(\.\d{3})?")
    for tag in tags:
        m = pattern.search(str(tag))
        if m:
            return m.group(0)
    return None


# ═══════════════════════════════════════════════════════════════
# ECS → STRATIX  (Elastic Common Schema)
# ═══════════════════════════════════════════════════════════════

class ECSToStratix:
    """
    Maps Elastic Common Schema (ECS) events to STRATIX-normalised events.

    ECS reference: https://www.elastic.co/guide/en/ecs/current/index.html
    STRATIX adds: intent layer, sovereignty metadata, AI telemetry classes.
    """

    # ECS event.category → STRATIX IntentCategory
    CATEGORY_MAP = {
        "authentication":   "credential_access",
        "file":             "collection",
        "network":          "command_and_control",
        "process":          "execution",
        "registry":         "persistence",
        "session":          "lateral_movement",
        "malware":          "execution",
        "intrusion_detection": "initial_access",
        "configuration":    "defence_evasion",
        "driver":           "privilege_escalation",
        "host":             "discovery",
        "iam":              "privilege_escalation",
        "threat":           "impact",
        "vulnerability":    "initial_access",
        "web":              "initial_access",
        "package":          "persistence",
    }

    def map(self, ecs_event: dict[str, Any]) -> dict[str, Any]:
        """Convert a single ECS event dict to a STRATIX event dict."""
        stratix = {
            "class_uid":    4001,         # OCSF: Detection Finding
            "category_uid": 4,
            "time":         ecs_event.get("@timestamp", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   "Elastic Security",
                    "vendor": "Elastic NV",
                    "version": ecs_event.get("agent", {}).get("version", "unknown"),
                },
                "source_schema": "ECS",
                "stratix_mapper_version": "1.0.0",
            },
        }

        # ── Intent layer ──
        ecs_categories = ecs_event.get("event", {}).get("category", [])
        if isinstance(ecs_categories, str):
            ecs_categories = [ecs_categories]

        intent_cat = None
        for cat in ecs_categories:
            if cat in self.CATEGORY_MAP:
                intent_cat = self.CATEGORY_MAP[cat]
                break

        tags          = ecs_event.get("tags", [])
        technique_id  = _map_technique(tags)
        risk_score    = ecs_event.get("event", {}).get("risk_score", 50)
        confidence    = min(int(risk_score), 100)

        if intent_cat:
            stratix["intent"] = {
                "category":        intent_cat,
                "confidence_score": confidence,
            }
            if technique_id:
                stratix["intent"]["technique_id"] = technique_id

        # ── Sovereignty layer ──
        observer_geo = ecs_event.get("observer", {}).get("geo", {})
        host_geo     = ecs_event.get("host", {}).get("geo", {})
        country_code = (
            observer_geo.get("country_iso_code")
            or host_geo.get("country_iso_code")
        )

        stratix["sovereignty"] = {
            "source_schema": "ECS",
        }
        if country_code:
            stratix["sovereignty"]["data_residency"] = country_code.upper()

        # ── Pass through key ECS fields ──
        for field in ["host", "user", "process", "network", "file", "source", "destination"]:
            if field in ecs_event:
                stratix[f"ecs_{field}"] = ecs_event[field]

        # Raw event reference
        stratix["raw"] = ecs_event
        return stratix

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


# ═══════════════════════════════════════════════════════════════
# CIM → STRATIX  (Splunk Common Information Model)
# ═══════════════════════════════════════════════════════════════

class CIMToStratix:
    """
    Maps Splunk CIM-normalised events to STRATIX-normalised events.
    CIM reference: https://docs.splunk.com/Documentation/CIM
    """

    # Splunk CIM sourcetype patterns → STRATIX IntentCategory
    SOURCETYPE_MAP = {
        "authentication":      "credential_access",
        "change":              "defence_evasion",
        "change_analysis":     "defence_evasion",
        "endpoint":            "execution",
        "intrusion_detection": "initial_access",
        "malware":             "execution",
        "network_sessions":    "lateral_movement",
        "network_traffic":     "command_and_control",
        "performance":         "discovery",
        "vulnerabilities":     "initial_access",
        "web":                 "initial_access",
        "alerts":              "impact",
    }

    def map(self, cim_event: dict[str, Any]) -> dict[str, Any]:
        sourcetype = cim_event.get("sourcetype", "").lower()
        intent_cat = self.SOURCETYPE_MAP.get(sourcetype, "discovery")

        stratix = {
            "class_uid":    4001,
            "category_uid": 4,
            "time":         cim_event.get("_time", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   "Splunk",
                    "vendor": "Splunk Inc.",
                    "version": "unknown",
                },
                "source_schema": "Splunk-CIM",
                "stratix_mapper_version": "1.0.0",
            },
            "intent": {
                "category":         intent_cat,
                "confidence_score":  int(cim_event.get("severity_id", 50)),
            },
            "sovereignty": {
                "source_schema": "Splunk-CIM",
            },
        }

        # ATT&CK tag extraction from Splunk annotations
        annotations = cim_event.get("annotations", {})
        mitre_attacks = annotations.get("mitre_attack", [])
        technique_id = _map_technique(mitre_attacks)
        if technique_id:
            stratix["intent"]["technique_id"] = technique_id

        # Map standard CIM fields
        for field in ["src", "dest", "user", "action", "signature", "severity"]:
            if field in cim_event:
                stratix[f"cim_{field}"] = cim_event[field]

        stratix["raw"] = cim_event
        return stratix

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


# ═══════════════════════════════════════════════════════════════
# ASIM → STRATIX  (Microsoft Sentinel Advanced SIEM Info Model)
# ═══════════════════════════════════════════════════════════════

class ASIMToStratix:
    """
    Maps Microsoft Sentinel ASIM-normalised events to STRATIX events.
    ASIM reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization
    """

    ASIM_SCHEMA_MAP = {
        "AuditEvent":             "defence_evasion",
        "Authentication":         "credential_access",
        "Dns":                    "command_and_control",
        "File":                   "collection",
        "NetworkSession":         "lateral_movement",
        "Process":                "execution",
        "RegistryEvent":          "persistence",
        "UserManagement":         "privilege_escalation",
        "WebSession":             "initial_access",
    }

    def map(self, asim_event: dict[str, Any]) -> dict[str, Any]:
        schema    = asim_event.get("EventSchema", "")
        intent_cat = self.ASIM_SCHEMA_MAP.get(schema, "discovery")

        stratix = {
            "class_uid":    4001,
            "category_uid": 4,
            "time":         asim_event.get("TimeGenerated", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   asim_event.get("EventProduct", "Microsoft Sentinel"),
                    "vendor": "Microsoft Corporation",
                    "version": asim_event.get("EventSchemaVersion", "unknown"),
                },
                "source_schema": "ASIM",
                "stratix_mapper_version": "1.0.0",
            },
            "intent": {
                "category":         intent_cat,
                "confidence_score":  self._severity_to_score(asim_event.get("EventSeverity", "Informational")),
            },
            "sovereignty": {
                "source_schema": "ASIM",
            },
        }

        # EU Data Boundary flag
        workspace_region = asim_event.get("_ResourceId", "")
        if "europe" in workspace_region.lower() or "eu" in workspace_region.lower():
            stratix["sovereignty"]["data_residency"] = "EU"

        # ATT&CK mapping
        tags = asim_event.get("AdditionalFields", {}).get("Tactics", [])
        technique = _map_technique(tags if isinstance(tags, list) else [tags])
        if technique:
            stratix["intent"]["technique_id"] = technique

        # Standard ASIM fields pass-through
        for field in ["SrcIpAddr", "DstIpAddr", "ActorUsername", "EventResult", "EventResultDetails"]:
            if field in asim_event:
                stratix[f"asim_{field}"] = asim_event[field]

        stratix["raw"] = asim_event
        return stratix

    def _severity_to_score(self, severity: str) -> int:
        return {
            "Informational": 10,
            "Low": 30,
            "Medium": 55,
            "High": 75,
            "Critical": 95,
        }.get(severity, 50)

    def map_batch(self, events: list[dict]) -> list[dict]:
        return [self.map(e) for e in events]


# ═══════════════════════════════════════════════════════════════
# Modbus → STRATIX  (OT industrial protocol adapter)
# ═══════════════════════════════════════════════════════════════

class ModbusToStratix:
    """
    Maps parsed Modbus frame data to STRATIX OT Layer events.

    Supports Modbus TCP and Modbus RTU decoded frames.
    Purdue Level: 1 (Field Devices) / 2 (Control Systems) depending on source.
    """

    # Modbus function codes → human-readable labels
    FUNCTION_CODES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x16: "Mask Write Register",
        0x17: "Read/Write Multiple Registers",
        0x2B: "Encapsulated Interface Transport",
    }

    # Write function codes — elevated risk
    WRITE_CODES = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}

    def map(self, frame: dict[str, Any], asset_id: str = "unknown",
            purdue_level: int = 1, data_residency: str = "BE") -> dict[str, Any]:
        """
        Parameters
        ----------
        frame          : dict — parsed Modbus frame fields
        asset_id       : str  — unique identifier of the PLC/device
        purdue_level   : int  — Purdue Model level (0–5)
        data_residency : str  — ISO 3166-1 alpha-2 country code
        """
        fn_code  = frame.get("function_code", 0)
        is_write = fn_code in self.WRITE_CODES

        # Anomaly scoring — writes to coils/registers are higher risk
        confidence = 75 if is_write else 20

        stratix = {
            "class_uid":    5001,         # OCSF: Device Activity
            "category_uid": 5,
            "time":         frame.get("timestamp", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   "Modbus Protocol Adapter",
                    "vendor": "Intelligent Consulting BV",
                    "version": "1.0.0",
                },
                "source_schema": "Modbus",
                "stratix_mapper_version": "1.0.0",
            },
            "intent": {
                "category":         "execution" if is_write else "discovery",
                "confidence_score":  confidence,
                "kill_chain_phase":  "actions_on_objectives" if is_write else "reconnaissance",
            },
            "ot": {
                "event_class":        "industrial_protocol_event",
                "asset_id":           asset_id,
                "purdue_level":       purdue_level,
                "protocol":           "Modbus",
                "function_code":      fn_code,
                "function_name":      self.FUNCTION_CODES.get(fn_code, f"Unknown (0x{fn_code:02X})"),
                "is_write_operation": is_write,
                "unit_id":            frame.get("unit_id"),
                "transaction_id":     frame.get("transaction_id"),
                "data_address":       frame.get("data_address"),
                "data_value":         frame.get("data_value"),
                "src_ip":             frame.get("src_ip"),
                "dst_ip":             frame.get("dst_ip"),
                "src_port":           frame.get("src_port"),
                "dst_port":           frame.get("dst_port", 502),
            },
            "sovereignty": {
                "data_residency":  data_residency,
                "classification":  "restricted",
                "nis2_category":   "essential_entity",
                "source_schema":   "Modbus",
            },
        }
        return stratix

    def map_batch(self, frames: list[dict], **kwargs) -> list[dict]:
        return [self.map(f, **kwargs) for f in frames]


# ═══════════════════════════════════════════════════════════════
# DNP3 → STRATIX  (OT industrial protocol adapter)
# ═══════════════════════════════════════════════════════════════

class DNP3ToStratix:
    """
    Maps parsed DNP3 frame data to STRATIX OT Layer events.
    DNP3 is common in energy, water, and utilities — NIS2 critical sectors.
    Purdue Level: 1–2.
    """

    FUNCTION_CODES = {
        0x00: "Confirm",
        0x01: "Read",
        0x02: "Write",
        0x03: "Select",
        0x04: "Operate",
        0x05: "Direct Operate",
        0x06: "Direct Operate NR",
        0x07: "Immed Freeze",
        0x08: "Immed Freeze NR",
        0x09: "Freeze and Clear",
        0x0A: "Freeze and Clear NR",
        0x0D: "Cold Restart",
        0x0E: "Warm Restart",
        0x14: "Authentication Request",
        0x20: "Unsolicited Response",
        0x81: "Response",
        0x82: "Unsolicited Response",
    }

    HIGH_RISK_CODES = {0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E}

    def map(self, frame: dict[str, Any], asset_id: str = "unknown",
            purdue_level: int = 2, data_residency: str = "BE") -> dict[str, Any]:
        fn_code   = frame.get("function_code", 0x01)
        is_high   = fn_code in self.HIGH_RISK_CODES

        stratix = {
            "class_uid":    5001,
            "category_uid": 5,
            "time":         frame.get("timestamp", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   "DNP3 Protocol Adapter",
                    "vendor": "Intelligent Consulting BV",
                    "version": "1.0.0",
                },
                "source_schema": "DNP3",
                "stratix_mapper_version": "1.0.0",
            },
            "intent": {
                "category":         "impact" if is_high else "discovery",
                "confidence_score":  80 if is_high else 25,
                "kill_chain_phase":  "actions_on_objectives" if is_high else "reconnaissance",
                "blast_radius":      ["operational_technology", "critical_infrastructure"] if is_high else [],
            },
            "ot": {
                "event_class":        "industrial_protocol_event",
                "asset_id":           asset_id,
                "purdue_level":       purdue_level,
                "protocol":           "DNP3",
                "function_code":      fn_code,
                "function_name":      self.FUNCTION_CODES.get(fn_code, f"Unknown (0x{fn_code:02X})"),
                "is_high_risk":       is_high,
                "master_address":     frame.get("master_address"),
                "outstation_address": frame.get("outstation_address"),
                "object_group":       frame.get("object_group"),
                "object_variation":   frame.get("object_variation"),
                "src_ip":             frame.get("src_ip"),
                "dst_ip":             frame.get("dst_ip"),
            },
            "sovereignty": {
                "data_residency": data_residency,
                "classification": "sovereign",
                "nis2_category":  "essential_entity",
                "source_schema":  "DNP3",
            },
        }
        return stratix

    def map_batch(self, frames: list[dict], **kwargs) -> list[dict]:
        return [self.map(f, **kwargs) for f in frames]


# ═══════════════════════════════════════════════════════════════
# OPC-UA → STRATIX  (OT industrial protocol adapter)
# ═══════════════════════════════════════════════════════════════

class OPCUAToStratix:
    """
    Maps OPC Unified Architecture (OPC-UA) events to STRATIX OT Layer events.
    OPC-UA is the primary protocol for cross-vendor OT interoperability.
    Purdue Level: 2–3.
    """

    SERVICE_MAP = {
        "Read":                  ("discovery",  "reconnaissance",       20),
        "Write":                 ("execution",  "actions_on_objectives", 75),
        "Browse":                ("discovery",  "reconnaissance",       15),
        "Call":                  ("execution",  "exploitation",         65),
        "CreateSession":         ("lateral_movement", "installation",   50),
        "ActivateSession":       ("lateral_movement", "installation",   55),
        "CloseSession":          ("defence_evasion", "installation",    30),
        "CreateSubscription":    ("collection", "actions_on_objectives",60),
        "DeleteSubscription":    ("defence_evasion", "installation",    35),
        "Publish":               ("collection", "actions_on_objectives",40),
        "AddNodes":              ("persistence", "installation",        70),
        "DeleteNodes":           ("defence_evasion", "actions_on_objectives", 75),
        "TransferSubscriptions": ("lateral_movement", "actions_on_objectives", 65),
    }

    def map(self, event: dict[str, Any], asset_id: str = "unknown",
            purdue_level: int = 3, data_residency: str = "BE") -> dict[str, Any]:
        service   = event.get("service_type", "Read")
        cat, phase, score = self.SERVICE_MAP.get(service, ("discovery", "reconnaissance", 20))

        stratix = {
            "class_uid":    5001,
            "category_uid": 5,
            "time":         event.get("timestamp", _now_iso()),
            "metadata": {
                "version": "1.3.0",
                "product": {
                    "name":   "OPC-UA Protocol Adapter",
                    "vendor": "Intelligent Consulting BV",
                    "version": "1.0.0",
                },
                "source_schema": "OPC-UA",
                "stratix_mapper_version": "1.0.0",
            },
            "intent": {
                "category":         cat,
                "confidence_score":  score,
                "kill_chain_phase":  phase,
            },
            "ot": {
                "event_class":       "industrial_protocol_event",
                "asset_id":          asset_id,
                "purdue_level":      purdue_level,
                "protocol":          "OPC-UA",
                "service_type":      service,
                "session_id":        event.get("session_id"),
                "node_id":           event.get("node_id"),
                "endpoint_url":      event.get("endpoint_url"),
                "security_mode":     event.get("security_mode"),
                "security_policy":   event.get("security_policy"),
                "client_ip":         event.get("client_ip"),
                "server_ip":         event.get("server_ip"),
                "status_code":       event.get("status_code"),
                "user_identity":     event.get("user_identity"),
            },
            "sovereignty": {
                "data_residency": data_residency,
                "classification": "restricted",
                "nis2_category":  "essential_entity",
                "source_schema":  "OPC-UA",
            },
        }
        return stratix

    def map_batch(self, events: list[dict], **kwargs) -> list[dict]:
        return [self.map(e, **kwargs) for e in events]


# ─────────────────────────────────────────────────────────────
# Mapper factory
# ─────────────────────────────────────────────────────────────

MAPPER_REGISTRY: dict[str, Any] = {
    "ecs":     ECSToStratix,
    "cim":     CIMToStratix,
    "asim":    ASIMToStratix,
    "modbus":  ModbusToStratix,
    "dnp3":    DNP3ToStratix,
    "opc-ua":  OPCUAToStratix,
}

def get_mapper(source_schema: str):
    """
    Factory function returning the correct mapper instance.

    Usage
    -----
    mapper = get_mapper("ecs")
    stratix_event = mapper.map(raw_event)
    """
    key = source_schema.lower()
    if key not in MAPPER_REGISTRY:
        raise ValueError(f"No STRATIX mapper registered for '{source_schema}'. "
                         f"Available: {list(MAPPER_REGISTRY.keys())}")
    return MAPPER_REGISTRY[key]()
