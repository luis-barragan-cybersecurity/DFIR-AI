"""Typed schemas for findings and pins."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNCERTAIN = "uncertain"
    UNKNOWN = "unknown"


class LocatorType(StrEnum):
    REGISTRY_PATH = "registry_path"
    FILE_OFFSET = "file_offset"
    SQL_ROW = "sql_row"
    LOG_LINE = "log_line"
    MEMORY_VAD = "memory_vad"
    EVTX_RECORD_ID = "evtx_record_id"
    PLIST_KEY = "plist_key"
    JOURNAL_CURSOR = "journal_cursor"
    AUDIT_MSG_ID = "audit_msg_id"


class Locator(BaseModel):
    type: LocatorType
    value: str = Field(min_length=1)


class Pin(BaseModel):
    artifact: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    locator: Locator
    raw_excerpt: str = Field(min_length=1, description="Hex, base64, or short text snippet of underlying bytes")
    captured_at: datetime


class Finding(BaseModel):
    finding_id: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    confidence: Confidence
    pins: list[Pin] = Field(min_length=1)
    mitre_attck: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)

    @field_validator("pins")
    @classmethod
    def at_least_one_pin(cls, v: list[Pin]) -> list[Pin]:
        if len(v) < 1:
            raise ValueError("Finding requires at least one pin (use chain_acknowledge_gap to refuse instead)")
        return v


class RegistryValueType(StrEnum):
    REG_NONE = "REG_NONE"
    REG_SZ = "REG_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"
    REG_BINARY = "REG_BINARY"
    REG_DWORD = "REG_DWORD"
    REG_DWORD_BIG_ENDIAN = "REG_DWORD_BIG_ENDIAN"
    REG_LINK = "REG_LINK"
    REG_MULTI_SZ = "REG_MULTI_SZ"
    REG_RESOURCE_LIST = "REG_RESOURCE_LIST"
    REG_FULL_RESOURCE_DESCRIPTOR = "REG_FULL_RESOURCE_DESCRIPTOR"
    REG_RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST"
    REG_QWORD = "REG_QWORD"
    UNKNOWN = "UNKNOWN"


class RegistryValue(BaseModel):
    name: str
    value_type: RegistryValueType
    value: Any = None
    raw_hex: str = Field(default="", description="Hex of underlying cell bytes for evidence pinning")


class RegistryKey(BaseModel):
    path: str
    timestamp: datetime | None = None
    subkeys: list[str] = Field(default_factory=list)
    values: list[RegistryValue] = Field(default_factory=list)
    hive_type: str | None = None
