from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable, Mapping, Sequence

from .disclosure import DatasetPolicySet, DisclosureAction
from .models import DataClass
from .policy import Policy


class RecipeRole(StrEnum):
    PRIMARY = "PRIMARY"
    CANDIDATE = "CANDIDATE"
    FALLBACK = "FALLBACK"
    RETIRED = "RETIRED"


class EvidenceProvenance(StrEnum):
    DECLARED = "DECLARED"
    STRUCTURAL = "STRUCTURAL"
    DETECTED = "DETECTED"
    AGENT_SUSPECTED = "AGENT_SUSPECTED"
    CROSS_CONFIRMED = "CROSS_CONFIRMED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PrivacyRecipeField:
    field: str
    data_class: DataClass
    action: DisclosureAction
    provenance: EvidenceProvenance
    evidence: tuple[str, ...]
    contradictions: tuple[str, ...] = ()


@dataclass(frozen=True)
class PrivacyRecipe:
    recipe_id: str
    dispatch_key: str
    dataset_id: str
    dataset_rule: str
    schema_fingerprint: str
    policy_version: str
    purpose: str
    operation: str
    destination: str
    role: RecipeRole
    reusable: bool
    created_at: str
    fields: tuple[PrivacyRecipeField, ...]
    contradictions: int = 0

    def schema(self) -> dict[str, DataClass]:
        return {item.field: item.data_class for item in self.fields}

    def actions(self) -> dict[str, DisclosureAction]:
        return {item.field: item.action for item in self.fields}


@dataclass(frozen=True)
class CompileResult:
    recipe: PrivacyRecipe
    cache_hit: bool
    stages: tuple[str, ...]


Detector = Callable[[str, Sequence[Any]], DataClass | str | None]


_ACTION_RANK = {
    DisclosureAction.REVEAL: 0,
    DisclosureAction.MASKED: 1,
    DisclosureAction.HANDLE: 2,
    DisclosureAction.AGGREGATE: 3,
    DisclosureAction.DENY: 4,
}

# Deterministic, bounded field-name signals. They are intentionally conservative.
_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], DataClass], ...] = (
    (re.compile(r"(^|[_\-.])(iban|account_?number|bank_?account)($|[_\-.])", re.I), DataClass.IBAN),
    (re.compile(r"(^|[_\-.])(email|e_?mail|mail_?address)($|[_\-.])", re.I), DataClass.EMAIL),
    (re.compile(r"(^|[_\-.])(phone|telephone|mobile|mobil|telefon)($|[_\-.])", re.I), DataClass.PHONE),
    (re.compile(r"(^|[_\-.])(birth|dob|geburt)($|[_\-.])", re.I), DataClass.BIRTH_DATE),
    (re.compile(r"(^|[_\-.])(address|street|strasse|straße|postcode|postal_?code)($|[_\-.])", re.I), DataClass.ADDRESS),
    (re.compile(r"(^|[_\-.])(diagnosis|diagnose|health|medical|krankheit|kranktage)($|[_\-.])", re.I), DataClass.HEALTH_DATA),
    (re.compile(r"(^|[_\-.])(password|passwd|secret|api_?key|access_?token|private_?key)($|[_\-.])", re.I), DataClass.SECRET),
    (re.compile(r"(^|[_\-.])(name|first_?name|last_?name|fullname|employee_?name|mitarbeiter_?name)($|[_\-.])", re.I), DataClass.PERSON),
)


def _schema_fingerprint(policy_version: str, schema: Mapping[str, DataClass | str]) -> str:
    canonical = {
        str(field): (value.value if isinstance(value, DataClass) else str(value))
        for field, value in sorted(schema.items())
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(policy_version.encode("utf-8") + b"\0" + payload).hexdigest()


def _coerce_class(value: DataClass | str | None) -> DataClass | None:
    if value is None:
        return None
    return value if isinstance(value, DataClass) else DataClass(str(value))


def _structural_class(field: str) -> DataClass | None:
    normalized = field.strip().replace(" ", "_")
    for pattern, data_class in _FIELD_PATTERNS:
        if pattern.search(normalized):
            return data_class
    return None


def _safe_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PrivacyRecipeCompiler:
    """Compile privacy classification + disclosure decisions once per exact context.

    Hot-path lookup is one exact encrypted-state key. There is no global candidate scan.
    Agent hints are evidence only: they can make the compiled action stricter, never more
    permissive than independently derived evidence/policy.
    """

    RECIPE_KIND = "privacy-recipe"
    CANDIDATE_KIND = "privacy-recipe-candidate"

    def __init__(
        self,
        runtime: Any,
        policy: Policy,
        datasets: DatasetPolicySet,
        *,
        detector: Detector | None = None,
    ) -> None:
        self.runtime = runtime
        self.policy = policy
        self.datasets = datasets
        self.detector = detector

    def _dispatch_key(
        self,
        *,
        dataset_id: str,
        schema_fingerprint: str,
        purpose: str,
        operation: str,
        destination: str,
    ) -> str:
        material = "\0".join(
            [dataset_id, schema_fingerprint, self.policy.version, purpose, operation, destination]
        )
        return _safe_id(material)

    def _load(self, key: str) -> PrivacyRecipe | None:
        raw = self.runtime.secure_state.get_json(self.RECIPE_KIND, key)
        if raw is None:
            return None
        return PrivacyRecipe(
            recipe_id=str(raw["recipe_id"]),
            dispatch_key=str(raw["dispatch_key"]),
            dataset_id=str(raw["dataset_id"]),
            dataset_rule=str(raw["dataset_rule"]),
            schema_fingerprint=str(raw["schema_fingerprint"]),
            policy_version=str(raw["policy_version"]),
            purpose=str(raw["purpose"]),
            operation=str(raw["operation"]),
            destination=str(raw["destination"]),
            role=RecipeRole(raw["role"]),
            reusable=bool(raw["reusable"]),
            created_at=str(raw["created_at"]),
            contradictions=int(raw.get("contradictions", 0)),
            fields=tuple(
                PrivacyRecipeField(
                    field=str(item["field"]),
                    data_class=DataClass(item["data_class"]),
                    action=DisclosureAction(item["action"]),
                    provenance=EvidenceProvenance(item["provenance"]),
                    evidence=tuple(str(x) for x in item.get("evidence", [])),
                    contradictions=tuple(str(x) for x in item.get("contradictions", [])),
                )
                for item in raw["fields"]
            ),
        )

    @staticmethod
    def _serialize(recipe: PrivacyRecipe) -> dict[str, Any]:
        raw = asdict(recipe)
        raw["role"] = recipe.role.value
        for item, field in zip(raw["fields"], recipe.fields):
            item["data_class"] = field.data_class.value
            item["action"] = field.action.value
            item["provenance"] = field.provenance.value
        return raw

    def get_or_compile(
        self,
        schema: Mapping[str, DataClass | str],
        *,
        dataset_id: str,
        purpose: str,
        operation: str,
        destination: str,
        samples: Sequence[Mapping[str, Any]] = (),
        agent_hints: Mapping[str, DataClass | str] | None = None,
    ) -> CompileResult:
        fingerprint = _schema_fingerprint(self.policy.version, schema)
        key = self._dispatch_key(
            dataset_id=dataset_id,
            schema_fingerprint=fingerprint,
            purpose=purpose,
            operation=operation,
            destination=destination,
        )
        cached = self._load(key)
        if cached is not None and cached.reusable and cached.role is RecipeRole.PRIMARY:
            return CompileResult(cached, True, ("RECIPE",))

        result = self.compile(
            schema,
            dataset_id=dataset_id,
            purpose=purpose,
            operation=operation,
            destination=destination,
            samples=samples,
            agent_hints=agent_hints,
            schema_fingerprint=fingerprint,
            dispatch_key=key,
        )
        if result.recipe.reusable:
            self.runtime.secure_state.put_json(self.RECIPE_KIND, key, self._serialize(result.recipe))
        else:
            candidate_id = f"{key}:{result.recipe.recipe_id}"
            self.runtime.secure_state.put_json(self.CANDIDATE_KIND, candidate_id, self._serialize(result.recipe))
        return result

    def compile(
        self,
        schema: Mapping[str, DataClass | str],
        *,
        dataset_id: str,
        purpose: str,
        operation: str,
        destination: str,
        samples: Sequence[Mapping[str, Any]] = (),
        agent_hints: Mapping[str, DataClass | str] | None = None,
        schema_fingerprint: str | None = None,
        dispatch_key: str | None = None,
    ) -> CompileResult:
        rule = self.datasets.resolve(dataset_id)
        if rule is None:
            raise ValueError("BBM_DATASET_CLASSIFICATION_REQUIRED")
        purpose_rule = rule.purposes.get(purpose)
        if purpose_rule is None:
            raise ValueError("BBM_DATASET_PURPOSE_DENIED")

        fingerprint = schema_fingerprint or _schema_fingerprint(self.policy.version, schema)
        key = dispatch_key or self._dispatch_key(
            dataset_id=dataset_id,
            schema_fingerprint=fingerprint,
            purpose=purpose,
            operation=operation,
            destination=destination,
        )

        hints = agent_hints or {}
        stages: set[str] = set()
        fields: list[PrivacyRecipeField] = []
        total_contradictions = 0

        for field, declared_raw in schema.items():
            evidence: list[tuple[str, DataClass]] = []
            contradictions: list[str] = []

            declared = _coerce_class(declared_raw)
            if declared is not None and declared is not DataClass.UNKNOWN:
                evidence.append(("DECLARED", declared))
                stages.add("DECLARED")

            structural = _structural_class(str(field))
            if structural is not None:
                evidence.append(("STRUCTURAL", structural))
                stages.add("STRUCTURAL")

            if self.detector is not None:
                values = [row[field] for row in samples if field in row][:32]
                detected = _coerce_class(self.detector(str(field), values))
                if detected is not None and detected is not DataClass.UNKNOWN:
                    evidence.append(("DETECTED", detected))
                    stages.add("DETECTOR")

            hinted = _coerce_class(hints.get(str(field)))
            if hinted is not None and hinted is not DataClass.UNKNOWN:
                evidence.append(("AGENT_SUSPECTED", hinted))
                stages.add("AGENT_HINT")

            independent = [(source, dc) for source, dc in evidence if source != "AGENT_SUSPECTED"]
            distinct_independent = {dc for _, dc in independent}
            if len(distinct_independent) > 1:
                contradictions.extend(sorted(dc.value for dc in distinct_independent))
                total_contradictions += 1

            # Every candidate is evaluated through current dataset policy. Choose the
            # strictest resulting action, so an agent hint cannot widen disclosure.
            candidates = evidence or [("UNKNOWN", DataClass.UNKNOWN)]
            scored: list[tuple[int, str, DataClass, DisclosureAction]] = []
            for source, dc in candidates:
                action = purpose_rule.action_for(str(field), dc, rule.default_action)
                scored.append((_ACTION_RANK[action], source, dc, action))
            scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
            _, chosen_source, chosen_class, chosen_action = scored[0]

            confirming_sources = sorted(source for source, dc in independent if dc is chosen_class)
            if len(confirming_sources) >= 2:
                provenance = EvidenceProvenance.CROSS_CONFIRMED
            elif chosen_source == "DECLARED":
                provenance = EvidenceProvenance.DECLARED
            elif chosen_source == "STRUCTURAL":
                provenance = EvidenceProvenance.STRUCTURAL
            elif chosen_source == "DETECTED":
                provenance = EvidenceProvenance.DETECTED
            elif chosen_source == "AGENT_SUSPECTED":
                provenance = EvidenceProvenance.AGENT_SUSPECTED
            else:
                provenance = EvidenceProvenance.UNKNOWN

            fields.append(
                PrivacyRecipeField(
                    field=str(field),
                    data_class=chosen_class,
                    action=chosen_action,
                    provenance=provenance,
                    evidence=tuple(f"{source}:{dc.value}" for source, dc in evidence),
                    contradictions=tuple(contradictions),
                )
            )

        reusable = total_contradictions == 0 and all(
            item.provenance is not EvidenceProvenance.AGENT_SUSPECTED for item in fields
        )
        recipe = PrivacyRecipe(
            recipe_id="BBMPR-" + _safe_id(key + datetime.now(UTC).isoformat())[:20],
            dispatch_key=key,
            dataset_id=dataset_id,
            dataset_rule=rule.rule_id,
            schema_fingerprint=fingerprint,
            policy_version=self.policy.version,
            purpose=purpose,
            operation=operation,
            destination=destination,
            role=RecipeRole.PRIMARY if reusable else RecipeRole.CANDIDATE,
            reusable=reusable,
            created_at=datetime.now(UTC).isoformat(),
            fields=tuple(fields),
            contradictions=total_contradictions,
        )
        return CompileResult(recipe, False, tuple(sorted(stages or {"UNKNOWN"})))

    def invalidate(
        self,
        *,
        dataset_id: str,
        schema: Mapping[str, DataClass | str],
        purpose: str,
        operation: str,
        destination: str,
    ) -> None:
        fingerprint = _schema_fingerprint(self.policy.version, schema)
        key = self._dispatch_key(
            dataset_id=dataset_id,
            schema_fingerprint=fingerprint,
            purpose=purpose,
            operation=operation,
            destination=destination,
        )
        self.runtime.secure_state.delete(self.RECIPE_KIND, key)
