from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from .models import ClassPolicy, DataClass, QualityAction, QualityPolicy, TokenMode, Transform


@dataclass(frozen=True)
class Policy:
    version: str
    strict_structured_data: bool
    default_action: Transform
    unknown_field_action: QualityAction
    default_quality: QualityPolicy
    classes: dict[DataClass, ClassPolicy]

    def for_class(self, data_class: DataClass, purpose: str) -> ClassPolicy:
        rule = self.classes.get(data_class)
        if rule is None:
            return ClassPolicy(self.default_action, quality=self.default_quality)
        if rule.allowed_purposes and purpose not in rule.allowed_purposes:
            return replace(rule, action=Transform.DENY)
        return rule


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


def _read_with_extends(path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    seen = set(seen or set())
    path = path.resolve()
    if path in seen:
        raise ValueError(f"Policy inheritance cycle at {path.name}")
    seen.add(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = raw.get("extends")
    if not parent:
        return raw
    parent_path = (path.parent / str(parent)).resolve()
    if not parent_path.exists():
        raise ValueError(f"Policy parent does not exist: {parent}")
    return _deep_merge(_read_with_extends(parent_path, seen), raw)


def _quality(raw: dict[str, Any] | None, base: QualityPolicy | None = None) -> QualityPolicy:
    base = base or QualityPolicy()
    raw = raw or {}
    formats = raw.get("accepted_birth_date_formats", base.accepted_birth_date_formats)
    return QualityPolicy(
        on_null=QualityAction(raw.get("on_null", base.on_null.value)),
        on_empty=QualityAction(raw.get("on_empty", base.on_empty.value)),
        on_invalid=QualityAction(raw.get("on_invalid", base.on_invalid.value)),
        on_transform_error=QualityAction(raw.get("on_transform_error", base.on_transform_error.value)),
        accepted_birth_date_formats=tuple(str(x) for x in formats),
    )


def load_policy(path: str | Path) -> Policy:
    raw = _read_with_extends(Path(path))
    default_quality = _quality(raw.get("quality"))
    classes: dict[DataClass, ClassPolicy] = {}
    for name, item in raw.get("classes", {}).items():
        dc = DataClass(name)
        rehydrate = {
            str(target): frozenset(str(op) for op in operations)
            for target, operations in (item.get("rehydrate") or {}).items()
        }
        classes[dc] = ClassPolicy(
            action=Transform(item["action"]),
            token_mode=TokenMode(item.get("token_mode", "LEASE_HANDLE")),
            rehydrate=rehydrate,
            allowed_purposes=frozenset(item.get("allowed_purposes", [])),
            quality=_quality(item.get("quality"), default_quality),
        )
    return Policy(
        version=str(raw.get("version", "BBM/1")),
        strict_structured_data=bool(raw.get("strict_structured_data", True)),
        default_action=Transform(raw.get("default_action", "DENY")),
        unknown_field_action=QualityAction(raw.get("unknown_field_action", "SUPPRESS")),
        default_quality=default_quality,
        classes=classes,
    )
