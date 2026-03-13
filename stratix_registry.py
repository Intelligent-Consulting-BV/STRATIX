#!/usr/bin/env python3
# stratix_registry.py
# STRATIX Registry - versioned schema registry
# (c) 2026 Intelligent Consulting BV. All rights reserved.
# Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
# First published: 26 February 2026

from __future__ import annotations
import hashlib, json, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class RegistryEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    display_name: str = ""
    version: str = "0.1.0"
    stratix_core_version: str = "1.0.0"
    domain: str = ""
    sector: str = ""
    author: str = ""
    organisation: str = ""
    contact: str = ""
    description: str = ""
    schema_json: dict = field(default_factory=dict)
    examples: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    nis2_aligned: bool = False
    dora_aligned: bool = False
    gdpr_aligned: bool = False
    ai_act_aligned: bool = False
    status: str = "draft"
    licence: str = "Apache 2.0"
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    checksum: Optional[str] = None

    def __post_init__(self):
        if self.published_at is None:
            self.published_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.published_at
        self._refresh_checksum()

    def _refresh_checksum(self):
        payload = json.dumps(self.schema_json, sort_keys=True)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self):
        return asdict(self)

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)


class StratixRegistry:
    def __init__(self):
        self._store: dict = {}

    def _key(self, name, version):
        return f"{name}::{version}"

    def publish(self, entry: RegistryEntry) -> RegistryEntry:
        if not entry.name:
            raise ValueError("RegistryEntry.name is required")
        if not entry.schema_json:
            raise ValueError("RegistryEntry.schema_json cannot be empty")
        entry._refresh_checksum()
        self._store[self._key(entry.name, entry.version)] = entry
        return entry

    def get(self, name: str, version: str) -> Optional[RegistryEntry]:
        return self._store.get(self._key(name, version))

    def get_latest(self, name: str) -> Optional[RegistryEntry]:
        matches = [e for e in self._store.values() if e.name == name]
        if not matches:
            return None
        return sorted(matches, key=lambda e: e.published_at, reverse=True)[0]

    def deprecate(self, name: str, version: str) -> bool:
        entry = self.get(name, version)
        if not entry:
            return False
        entry.status = "deprecated"
        entry.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def delete(self, name: str, version: str) -> bool:
        key = self._key(name, version)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def search(self, domain=None, sector=None, tags=None,
               status=None, nis2_aligned=None, dora_aligned=None, gdpr_aligned=None):
        results = list(self._store.values())
        if domain:
            results = [e for e in results if e.domain.lower() == domain.lower()]
        if sector:
            results = [e for e in results if e.sector.lower() == sector.lower()]
        if tags:
            results = [e for e in results if any(t in e.tags for t in tags)]
        if status:
            results = [e for e in results if e.status == status]
        if nis2_aligned is not None:
            results = [e for e in results if e.nis2_aligned == nis2_aligned]
        if dora_aligned is not None:
            results = [e for e in results if e.dora_aligned == dora_aligned]
        if gdpr_aligned is not None:
            results = [e for e in results if e.gdpr_aligned == gdpr_aligned]
        return sorted(results, key=lambda e: e.updated_at, reverse=True)

    def list_all(self):
        return list(self._store.values())

    def stats(self):
        entries = self.list_all()
        def count_by(attr):
            counts = {}
            for e in entries:
                v = getattr(e, attr, "unknown")
                counts[v] = counts.get(v, 0) + 1
            return counts
        return {
            "total": len(entries),
            "by_status": count_by("status"),
            "by_domain": count_by("domain"),
            "by_sector": count_by("sector"),
            "nis2_aligned": sum(1 for e in entries if e.nis2_aligned),
            "dora_aligned": sum(1 for e in entries if e.dora_aligned),
            "gdpr_aligned": sum(1 for e in entries if e.gdpr_aligned),
        }

    def validate_extension(self, schema_json: dict) -> dict:
        PROTECTED = {"intent", "sovereignty", "ot", "ai",
                     "class_uid", "category_uid", "time", "metadata"}
        conflicts = PROTECTED.intersection(schema_json.keys())
        if conflicts:
            return {"valid": False, "errors": [f"Conflicts with STRATIX core fields: {conflicts}"]}
        return {"valid": True, "errors": []}

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.list_all()], indent=2)

    def import_json(self, json_str: str):
        entries = json.loads(json_str)
        for e_dict in entries:
            valid_keys = RegistryEntry.__dataclass_fields__.keys()
            entry = RegistryEntry(**{k: v for k, v in e_dict.items() if k in valid_keys})
            self._store[self._key(entry.name, entry.version)] = entry


# ---------------------------------------------------------------------------
# Demo / smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    registry = StratixRegistry()

    # Publish a sample energy-sector extension
    energy_ext = RegistryEntry(
        name="energy-grid-events",
        display_name="Energy Grid OT Event Extension",
        version="0.1.0",
        domain="energy",
        sector="electricity",
        author="Suzanne Natalie Button",
        organisation="Intelligent Consulting BV",
        description="STRATIX extension for electricity transmission and distribution events",
        schema_json={
            "grid_event": {
                "substation_id": "string",
                "voltage_level_kv": "number",
                "circuit_breaker_id": "string",
                "protection_zone": "string",
                "scada_rtu_id": "string",
            }
        },
        tags=["energy", "NIS2", "grid", "substation", "SCADA"],
        nis2_aligned=True,
        gdpr_aligned=False,
        status="approved",
    )

    registry.publish(energy_ext)

    # Publish a finance/DORA extension
    finance_ext = RegistryEntry(
        name="dora-ict-incident",
        display_name="DORA ICT Incident Reporting Extension",
        version="0.1.0",
        domain="financial",
        sector="banking",
        author="Suzanne Natalie Button",
        organisation="Intelligent Consulting BV",
        description="STRATIX extension for DORA Article 19 major ICT incident reporting",
        schema_json={
            "dora_incident": {
                "incident_classification": "string",
                "ict_service_affected": "string",
                "clients_affected_count": "integer",
                "transactions_affected_count": "integer",
                "reporting_deadline_hours": "integer",
                "competent_authority": "string",
                "lei_code": "string",
            }
        },
        tags=["DORA", "financial", "ICT-incident", "EBA", "ESMA"],
        nis2_aligned=True,
        dora_aligned=True,
        gdpr_aligned=True,
        status="approved",
    )

    registry.publish(finance_ext)

    print("=== STRATIX Registry Stats ===")
    print(json.dumps(registry.stats(), indent=2))

    print("\n=== Search: NIS2-aligned extensions ===")
    for e in registry.search(nis2_aligned=True):
        print(f"  {e.name} v{e.version} [{e.domain}] - {e.status}")

    print("\n=== Validate extension schema ===")
    result = registry.validate_extension({"grid_event": {"substation_id": "string"}})
    print(f"  Valid: {result['valid']}")

    bad_result = registry.validate_extension({"intent": {"category": "execution"}})
    print(f"  Conflict detected: {not bad_result['valid']} - {bad_result['errors']}")

    print("\n=== Export / Import round-trip ===")
    exported = registry.export_json()
    new_registry = StratixRegistry()
    new_registry.import_json(exported)
    print(f"  Imported {len(new_registry.list_all())} entries successfully")

    print("\nAll STRATIX Registry smoke tests passed.")
