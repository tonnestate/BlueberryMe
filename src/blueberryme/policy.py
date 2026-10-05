from __future__ import annotations

from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from .models import ClassPolicy, DataClass, FlowRule, Linkability, QualityAction, QualityPolicy, TokenMode, Transform


@dataclass(frozen=True)
class Policy:
    version: str
    strict_structured_data: bool
    default_action: Transform
    unknown_field_action: QualityAction
    default_quality: QualityPolicy
    classes: dict[DataClass, ClassPolicy]
    flows: tuple[FlowRule, ...] = ()
    default_linkability: Linkability = Linkability.LEASE

    def for_class(self, data_class: DataClass, purpose: str) -> ClassPolicy:
        rule = self.classes.get(data_class)
        if rule is None:
            return ClassPolicy(
                action=self.default_action, quality=self.default_quality, linkability=self.default_linkability
            )
        if rule.allowed_purposes and purpose not in rule.allowed_purposes:
            return replace(rule, action=Transform.DENY)
        return rule

    def flow_allowed(self, *, origin_scope: str, purpose: str, target: str, operation: str) -> bool:
        if not self.flows:
            return True
        for rule in self.flows:
            if not fnmatchcase(origin_scope, rule.origin_scope):
                continue
            if rule.purposes and purpose not in rule.purposes:
                continue
            allowed = rule.sinks.get(target, frozenset())
            if operation in allowed or "*" in allowed:
                return True
        return False


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if key == "extends":
            continue
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _load_raw(path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    seen = seen or set()
    resolved = path.resolve()
    if resolved in seen:
        raise ValueError("Policy inheritance cycle detected")
    seen.add(resolved)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = raw.get("extends")
    if parent:
        base = _load_raw(path.parent / str(parent), seen)
        return _deep_merge(base, raw)
    return raw


def _quality(raw: dict[str, Any] | None, default: QualityPolicy | None = None) -> QualityPolicy:
    base = default or QualityPolicy()
    raw = raw or {}
    return QualityPolicy(
        on_null=QualityAction(raw.get("on_null", base.on_null.value)),
        on_empty=QualityAction(raw.get("on_empty", base.on_empty.value)),
        on_invalid=QualityAction(raw.get("on_invalid", base.on_invalid.value)),
        on_transform_error=QualityAction(raw.get("on_transform_error", base.on_transform_error.value)),
        accepted_birth_date_formats=tuple(raw.get("accepted_birth_date_formats", base.accepted_birth_date_formats)),
    )


def load_policy_document(path: str | Path) -> dict[str, Any]:
    """Return the fully inherited policy document for extension modules."""
    return _load_raw(Path(path))


def load_policy(path: str | Path) -> Policy:
    raw = load_policy_document(path)
    default_quality = _quality(raw.get("quality"))
    default_linkability = Linkability(raw.get("default_linkability", "LEASE"))
    classes: dict[DataClass, ClassPolicy] = {}
    for name, item in (raw.get("classes") or {}).items():
        dc = DataClass(name)
        token_mode_raw = item.get("token_mode", "LEASE_HANDLE")
        if token_mode_raw != "LEASE_HANDLE":
            raise ValueError("BBM/1 v0.3 exposes random LEASE_HANDLE only to agents")
        rehydrate = {
            str(target): frozenset(str(op) for op in operations)
            for target, operations in (item.get("rehydrate") or {}).items()
        }
        classes[dc] = ClassPolicy(
            action=Transform(item.get("action", raw.get("default_action", "DENY"))),
            token_mode=TokenMode.LEASE_HANDLE,
            linkability=Linkability(item.get("linkability", default_linkability.value)),
            rehydrate=rehydrate,
            allowed_purposes=frozenset(str(x) for x in item.get("allowed_purposes", [])),
            quality=_quality(item.get("quality"), default_quality),
        )

    flows: list[FlowRule] = []
    for item in raw.get("flows", []) or []:
        flows.append(
            FlowRule(
                origin_scope=str(item.get("origin_scope", "*")),
                purposes=frozenset(str(x) for x in item.get("purposes", [])),
                sinks={
                    str(target): frozenset(str(op) for op in operations)
                    for target, operations in (item.get("sinks") or {}).items()
                },
            )
        )

    return Policy(
        version=str(raw.get("version", "BBM/1-draft-0.4")),
        strict_structured_data=bool(raw.get("strict_structured_data", True)),
        default_action=Transform(raw.get("default_action", "DENY")),
        unknown_field_action=QualityAction(raw.get("unknown_field_action", "PROTECT")),
        default_quality=default_quality,
        classes=classes,
        flows=tuple(flows),
        default_linkability=default_linkability,
    )
