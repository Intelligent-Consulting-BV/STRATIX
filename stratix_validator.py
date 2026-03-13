#!/usr/bin/env python3
"""
stratix-validator
=================
Python validation library for STRATIX schema conformance checking
at pipeline ingestion points.

© 2026 Intelligent Consulting BV. All rights reserved.
Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
Licence: Apache 2.0 (implementation use); STRATIX name and specification
         remain the exclusive intellectual property of Intelligent Consulting BV.
First published: 26 February 2026
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Enumerations — STRATIX controlled vocabularies
# ---------------------------------------------------------------------------

class IntentCategory(str, Enum):
    INITIAL_ACCESS        = "initial_access"
    EXECUTION             = "execution"
    PERSISTENCE           = "persistence"
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    DEFENCE_EVASION       = "defence_evasion"
    CREDENTIAL_ACCESS     = "credential_access"
    DISCOVERY             = "discovery"
    LATERAL_MOVEMENT      = "lateral_movement"
    COLLECTION            = "collection"
    COMMAND_AND_CONTROL   = "command_and_control"
    EXFILTRATION          = "exfiltration"
    IMPACT                = "impact"


class KillChainPhase(str, Enum):
    RECONNAISSANCE        = "reconnaissance"
    RESOURCE_DEVELOPMENT  = "resource_development"
    WEAPONISATION         = "weaponisation"
    DELIVERY              = "delivery"
    EXPLOITATION          = "exploitation"
    INSTALLATION          = "installation"
    COMMAND_AND_CONTROL   = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class DataClassification(str, Enum):
    PUBLIC        = "public"
    INTERNAL      = "internal"
    CONFIDENTIAL  = "confidential"
    RESTRICTED    = "restricted"
    SOVEREIGN     = "sovereign"


class NIS2Category(str, Enum):
    ESSENTIAL   = "essential_entity"
    IMPORTANT   = "important_entity"
    OUT_OF_SCOPE = "out_of_scope"


class EUCSAssuranceLevel(str, Enum):
    BASIC        = "basic"
    SUBSTANTIAL  = "substantial"
    HIGH         = "high"


class AIActClassification(str, Enum):
    UNACCEPTABLE  = "unacceptable"
    HIGH_RISK     = "high_risk"
    LIMITED_RISK  = "limited_risk"
    MINIMAL_RISK  = "minimal_risk"


class GDPRLawfulBasis(str, Enum):
    CONSENT               = "consent"
    CONTRACT              = "contract"
    LEGAL_OBLIGATION      = "legal_obligation"
    VITAL_INTERESTS       = "vital_interests"
    PUBLIC_TASK           = "public_task"
    LEGITIMATE_INTERESTS  = "legitimate_interests"


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

class ValidationResult:
    def __init__(self):
        self.valid: bool = True
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.layer_results: dict[str, bool] = {}

    def add_error(self, msg: str):
        self.errors.append(msg)
        self.valid = False

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "layer_results": self.layer_results,
        }

    def __repr__(self):
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------

class StratixValidator:
    """
    Validates events against the STRATIX schema specification.

    Usage
    -----
    validator = StratixValidator()
    result = validator.validate(event_dict)
    if not result.valid:
        for err in result.errors:
            print(err)
    """

    TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
    ISO3166_PATTERN       = re.compile(r"^[A-Z]{2}$")

    def __init__(self, strict: bool = True):
        """
        Parameters
        ----------
        strict : bool
            When True, missing optional-but-recommended fields raise warnings.
        """
        self.strict = strict

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def validate(self, event: dict[str, Any]) -> ValidationResult:
        result = ValidationResult()
        self._validate_ocsf_base(event, result)
        self._validate_intent_layer(event.get("intent"), result)
        self._validate_sovereignty_layer(event.get("sovereignty"), result)
        self._validate_ot_layer(event.get("ot"), result)
        self._validate_ai_layer(event.get("ai"), result)
        return result

    def validate_batch(self, events: list[dict]) -> list[ValidationResult]:
        return [self.validate(e) for e in events]

    # ------------------------------------------------------------------
    # OCSF base fields
    # ------------------------------------------------------------------

    def _validate_ocsf_base(self, event: dict, result: ValidationResult):
        required = ["class_uid", "category_uid", "time", "metadata"]
        for field in required:
            if field not in event:
                result.add_error(f"OCSF base: missing required field '{field}'")

        if "time" in event:
            try:
                datetime.fromisoformat(str(event["time"]).replace("Z", "+00:00"))
            except ValueError:
                result.add_error("OCSF base: 'time' must be ISO 8601 format")

        if "metadata" in event:
            meta = event["metadata"]
            if "version" not in meta:
                result.add_error("OCSF base: metadata.version is required")
            if "product" not in meta:
                result.add_warning("OCSF base: metadata.product is recommended")

        result.layer_results["ocsf_base"] = len(result.errors) == 0

    # ------------------------------------------------------------------
    # Layer 1: Intent
    # ------------------------------------------------------------------

    def _validate_intent_layer(self, intent: Optional[dict], result: ValidationResult):
        if intent is None:
            if self.strict:
                result.add_warning("STRATIX Layer 1: 'intent' block absent — behavioural attribution unavailable")
            result.layer_results["intent"] = False
            return

        errors_before = len(result.errors)

        # intent.category
        if "category" not in intent:
            result.add_error("intent.category is required")
        else:
            try:
                IntentCategory(intent["category"])
            except ValueError:
                valid = [e.value for e in IntentCategory]
                result.add_error(f"intent.category '{intent['category']}' invalid. Must be one of: {valid}")

        # intent.technique_id
        if "technique_id" in intent:
            if not self.TECHNIQUE_ID_PATTERN.match(intent["technique_id"]):
                result.add_error("intent.technique_id must match ATT&CK pattern e.g. T1078 or T1078.003")

        # intent.confidence_score
        if "confidence_score" in intent:
            score = intent["confidence_score"]
            if not isinstance(score, (int, float)) or not (0 <= score <= 100):
                result.add_error("intent.confidence_score must be a number between 0 and 100")

        # intent.kill_chain_phase
        if "kill_chain_phase" in intent:
            try:
                KillChainPhase(intent["kill_chain_phase"])
            except ValueError:
                valid = [e.value for e in KillChainPhase]
                result.add_error(f"intent.kill_chain_phase invalid. Must be one of: {valid}")

        # intent.blast_radius
        if "blast_radius" in intent:
            br = intent["blast_radius"]
            if not isinstance(br, list) or not all(isinstance(i, str) for i in br):
                result.add_error("intent.blast_radius must be a list of strings (asset class identifiers)")

        result.layer_results["intent"] = len(result.errors) == errors_before

    # ------------------------------------------------------------------
    # Layer 3: Sovereignty
    # ------------------------------------------------------------------

    def _validate_sovereignty_layer(self, sov: Optional[dict], result: ValidationResult):
        if sov is None:
            if self.strict:
                result.add_warning("STRATIX Layer 3: 'sovereignty' block absent — EU regulatory metadata unavailable")
            result.layer_results["sovereignty"] = False
            return

        errors_before = len(result.errors)

        # data_residency
        if "data_residency" in sov:
            if not self.ISO3166_PATTERN.match(str(sov["data_residency"])):
                result.add_error("sovereignty.data_residency must be ISO 3166-1 alpha-2 country code e.g. 'BE'")

        # classification
        if "classification" in sov:
            try:
                DataClassification(sov["classification"])
            except ValueError:
                valid = [e.value for e in DataClassification]
                result.add_error(f"sovereignty.classification invalid. Must be one of: {valid}")

        # gdpr_lawful_basis
        if "gdpr_lawful_basis" in sov:
            try:
                GDPRLawfulBasis(sov["gdpr_lawful_basis"])
            except ValueError:
                valid = [e.value for e in GDPRLawfulBasis]
                result.add_error(f"sovereignty.gdpr_lawful_basis invalid. Must be one of: {valid}")

        # nis2_category
        if "nis2_category" in sov:
            try:
                NIS2Category(sov["nis2_category"])
            except ValueError:
                valid = [e.value for e in NIS2Category]
                result.add_error(f"sovereignty.nis2_category invalid. Must be one of: {valid}")

        # eucs_assurance_level
        if "eucs_assurance_level" in sov:
            try:
                EUCSAssuranceLevel(sov["eucs_assurance_level"])
            except ValueError:
                valid = [e.value for e in EUCSAssuranceLevel]
                result.add_error(f"sovereignty.eucs_assurance_level invalid. Must be one of: {valid}")

        # ai_act_classification
        if "ai_act_classification" in sov:
            try:
                AIActClassification(sov["ai_act_classification"])
            except ValueError:
                valid = [e.value for e in AIActClassification]
                result.add_error(f"sovereignty.ai_act_classification invalid. Must be one of: {valid}")

        # dora_ict_asset
        if "dora_ict_asset" in sov:
            if not isinstance(sov["dora_ict_asset"], bool):
                result.add_error("sovereignty.dora_ict_asset must be a boolean")

        # access_log
        if "access_log" in sov:
            log = sov["access_log"]
            if not isinstance(log, list):
                result.add_error("sovereignty.access_log must be a list of access log entries")
            else:
                for i, entry in enumerate(log):
                    for req in ["accessor_id", "accessed_at", "signature"]:
                        if req not in entry:
                            result.add_error(f"sovereignty.access_log[{i}] missing required field '{req}'")

        result.layer_results["sovereignty"] = len(result.errors) == errors_before

    # ------------------------------------------------------------------
    # Layer 2: OT/ICS
    # ------------------------------------------------------------------

    def _validate_ot_layer(self, ot: Optional[dict], result: ValidationResult):
        if ot is None:
            result.layer_results["ot"] = True  # optional layer
            return

        errors_before = len(result.errors)
        valid_classes = [
            "plc_state_change", "scada_alarm", "process_deviation",
            "industrial_protocol_event", "zone_crossing",
            "engineering_workstation_action", "safety_system_event",
            "asset_inventory_change"
        ]
        if "event_class" not in ot:
            result.add_error("ot.event_class is required when 'ot' block is present")
        elif ot["event_class"] not in valid_classes:
            result.add_error(f"ot.event_class '{ot['event_class']}' invalid. Must be one of: {valid_classes}")

        if "asset_id" not in ot:
            result.add_warning("ot.asset_id is strongly recommended for asset correlation")

        if "purdue_level" in ot:
            if ot["purdue_level"] not in [0, 1, 2, 3, 4, 5]:
                result.add_error("ot.purdue_level must be an integer 0–5 (Purdue Model levels)")

        result.layer_results["ot"] = len(result.errors) == errors_before

    # ------------------------------------------------------------------
    # Layer 4: AI Telemetry
    # ------------------------------------------------------------------

    def _validate_ai_layer(self, ai: Optional[dict], result: ValidationResult):
        if ai is None:
            result.layer_results["ai"] = True  # optional layer
            return

        errors_before = len(result.errors)
        valid_classes = [
            "model_invocation", "prompt_injection_attempt", "tool_use",
            "decision_trace", "autonomous_action", "human_escalation",
            "model_drift_signal", "governance_audit_record"
        ]
        if "event_class" not in ai:
            result.add_error("ai.event_class is required when 'ai' block is present")
        elif ai["event_class"] not in valid_classes:
            result.add_error(f"ai.event_class '{ai['event_class']}' invalid. Must be one of: {valid_classes}")

        if "model_id" not in ai:
            result.add_warning("ai.model_id is strongly recommended for model governance tracking")

        if "inference_location" in ai:
            if not self.ISO3166_PATTERN.match(str(ai.get("inference_location", ""))):
                result.add_error("ai.inference_location must be ISO 3166-1 alpha-2 country code e.g. 'BE'")

        if "autonomous_action" == ai.get("event_class"):
            if "authorisation_boundary" not in ai:
                result.add_error("ai.authorisation_boundary is required for autonomous_action events")
            if "action_type" not in ai:
                result.add_error("ai.action_type is required for autonomous_action events")

        result.layer_results["ai"] = len(result.errors) == errors_before


# ---------------------------------------------------------------------------
# Access log helper — generates STRATIX-compliant signed access log entries
# ---------------------------------------------------------------------------

class AccessLogEntry:
    """Creates immutable, signed access log entries for sovereignty.access_log."""

    @staticmethod
    def create(accessor_id: str, event_id: str, purpose: str) -> dict:
        entry = {
            "accessor_id": accessor_id,
            "event_id": event_id,
            "purpose": purpose,
            "accessed_at": datetime.now(timezone.utc).isoformat(),
            "entry_id": str(uuid.uuid4()),
        }
        payload = json.dumps(entry, sort_keys=True)
        entry["signature"] = hashlib.sha256(payload.encode()).hexdigest()
        return entry


# ---------------------------------------------------------------------------
# Pipeline ingestion wrapper
# ---------------------------------------------------------------------------

class StratixPipeline:
    """
    Wraps a data pipeline ingestion point with STRATIX validation.
    Drop-in wrapper for Kafka consumers, Logstash outputs, Cribl destinations, etc.

    Usage
    -----
    pipeline = StratixPipeline(strict=True, on_invalid="quarantine")
    for event in incoming_events:
        pipeline.process(event)
    """

    def __init__(self, strict: bool = True, on_invalid: str = "quarantine"):
        """
        Parameters
        ----------
        strict       : bool — pass to StratixValidator
        on_invalid   : str  — "quarantine" | "drop" | "passthrough"
        """
        self.validator   = StratixValidator(strict=strict)
        self.on_invalid  = on_invalid
        self._valid_count   = 0
        self._invalid_count = 0
        self._quarantine: list[dict] = []

    def process(self, event: dict) -> Optional[dict]:
        result = self.validator.validate(event)
        if result.valid:
            self._valid_count += 1
            return event
        else:
            self._invalid_count += 1
            if self.on_invalid == "quarantine":
                self._quarantine.append({"event": event, "errors": result.errors})
                return None
            elif self.on_invalid == "drop":
                return None
            else:  # passthrough
                return event

    @property
    def stats(self) -> dict:
        return {
            "valid": self._valid_count,
            "invalid": self._invalid_count,
            "quarantined": len(self._quarantine),
        }

    @property
    def quarantine(self) -> list[dict]:
        return self._quarantine


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python stratix_validator.py <event.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        event = json.load(f)

    validator = StratixValidator(strict=True)
    result = validator.validate(event)
    print(result)
    sys.exit(0 if result.valid else 1)
