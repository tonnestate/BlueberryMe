from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
import hashlib
import secrets
from typing import Any, Mapping, Sequence

from .models import DataClass
from .policy import load_policy_document


class DisclosureAction(StrEnum):
    DENY = "DENY"
    AGGREGATE = "AGGREGATE"
    HANDLE = "HANDLE"
    MASKED = "MASKED"
    REVEAL = "REVEAL"


class ReceiptDecision(StrEnum):
    VERIFIED_PROTECTED = "VERIFIED_PROTECTED"
    AUTHORIZED_DISCLOSURE = "AUTHORIZED_DISCLOSURE"
    BLOCKED = "BLOCKED"
    UNVERIFIED = "UNVERIFIED"


_DISCLOSURE_RANK = {
    DisclosureAction.REVEAL: 0,
    DisclosureAction.MASKED: 1,
    DisclosureAction.HANDLE: 2,
    DisclosureAction.AGGREGATE: 3,
    DisclosureAction.DENY: 4,
}


def _stricter_action(left: DisclosureAction, right: DisclosureAction) -> DisclosureAction:
    """Return the action that releases less row-level information."""
    return left if _DISCLOSURE_RANK[left] >= _DISCLOSURE_RANK[right] else right


@dataclass(frozen=True)
class DatasetPurposeRule:
    operations: frozenset[str]
    destinations: frozenset[str]
    agents: frozenset[str]
    lease_scopes: frozenset[str]
    max_rows: int | None
    max_reveal_rows_per_lease: int | None
    default_action: DisclosureAction
    class_actions: Mapping[DataClass, DisclosureAction]
    field_actions: Mapping[str, DisclosureAction]

    def action_for(self, field: str, data_class: DataClass, dataset_default: DisclosureAction) -> DisclosureAction:
        for pattern, action in self.field_actions.items():
            if fnmatchcase(field, pattern):
                return action
        if data_class in self.class_actions:
            return self.class_actions[data_class]
        return self.default_action or dataset_default


@dataclass(frozen=True)
class DatasetRule:
    rule_id: str
    match: str
    risk: str
    default_action: DisclosureAction
    purposes: Mapping[str, DatasetPurposeRule]


@dataclass(frozen=True)
class DatasetPolicySet:
    rules: tuple[DatasetRule, ...]

    def resolve(self, dataset_id: str) -> DatasetRule | None:
        for rule in self.rules:
            if fnmatchcase(dataset_id, rule.match):
                return rule
        return None


@dataclass(frozen=True)
class PrivacyReceipt:
    receipt_id: str
    timestamp: str
    decision: ReceiptDecision
    reason_code: str
    path_coverage: str
    dataset_id: str
    dataset_rule: str | None
    risk: str | None
    surface: str
    purpose: str
    operation: str
    destination: str
    rows_observed: int
    rows_released: int
    protected_values: int
    denied_values: int
    aggregate_only_values: int
    masked_values: int
    raw_values_released: int
    raw_sensitive_values_released: int
    unknown_fields: int
    data_classes_observed: tuple[str, ...]


@dataclass(frozen=True)
class EgressResult:
    records: tuple[dict[str, Any], ...]
    receipt: PrivacyReceipt


def _actions(raw: Mapping[str, Any] | None) -> dict[str, DisclosureAction]:
    return {str(key): DisclosureAction(str(value)) for key, value in (raw or {}).items()}


def load_dataset_policies(path: str | Path) -> DatasetPolicySet:
    raw = load_policy_document(path)
    rules: list[DatasetRule] = []
    for item in raw.get("datasets", []) or []:
        default_action = DisclosureAction(str(item.get("default_action", "DENY")))
        if default_action in {DisclosureAction.REVEAL, DisclosureAction.MASKED}:
            raise ValueError("Dataset default may not disclose raw/partial values; authorize them explicitly")
        purposes: dict[str, DatasetPurposeRule] = {}
        for purpose, value in (item.get("purposes") or {}).items():
            class_actions: dict[DataClass, DisclosureAction] = {}
            for name, action in _actions(value.get("classes")).items():
                data_class = DataClass(name)
                parsed = DisclosureAction(action)
                if data_class is DataClass.SECRET and parsed in {DisclosureAction.REVEAL, DisclosureAction.MASKED}:
                    raise ValueError("SECRET may not be disclosed; use a capability-bound target operation")
                if data_class is DataClass.UNKNOWN and parsed in {DisclosureAction.REVEAL, DisclosureAction.MASKED}:
                    raise ValueError("UNKNOWN may not be disclosed by class; use an explicit field rule after classification")
                class_actions[data_class] = parsed

            field_actions = _actions(value.get("fields"))
            for pattern, parsed in field_actions.items():
                if pattern == "*" and parsed in {DisclosureAction.REVEAL, DisclosureAction.MASKED}:
                    raise ValueError("Wildcard field disclosure is forbidden; enumerate a field/class explicitly")

            purpose_default = DisclosureAction(str(value.get("default_action", default_action.value)))
            if purpose_default in {DisclosureAction.REVEAL, DisclosureAction.MASKED}:
                raise ValueError("Purpose default may not disclose raw/partial values; authorize them explicitly")

            agents = frozenset(str(x) for x in value.get("agents", ["*"]))
            sensitive_reveal = any(
                action is DisclosureAction.REVEAL and data_class is not DataClass.PUBLIC
                for data_class, action in class_actions.items()
            ) or any(action is DisclosureAction.REVEAL for action in field_actions.values())
            if sensitive_reveal and any(any(ch in agent for ch in "*?[") for agent in agents):
                raise ValueError("Sensitive REVEAL requires concrete agent ids; wildcard agents are forbidden")

            reveal_budget_raw = value.get("max_reveal_rows_per_lease")
            reveal_budget = int(reveal_budget_raw) if reveal_budget_raw is not None else None
            if reveal_budget is not None and reveal_budget < 1:
                raise ValueError("max_reveal_rows_per_lease must be >= 1")
            if sensitive_reveal and reveal_budget is None:
                raise ValueError("Sensitive REVEAL requires max_reveal_rows_per_lease")

            purposes[str(purpose)] = DatasetPurposeRule(
                operations=frozenset(str(x) for x in value.get("operations", ["*"])),
                destinations=frozenset(str(x) for x in value.get("destinations", ["*"])),
                agents=agents,
                lease_scopes=frozenset(str(x) for x in value.get("lease_scopes", ["*"])),
                max_rows=(int(value["max_rows"]) if value.get("max_rows") is not None else None),
                max_reveal_rows_per_lease=reveal_budget,
                default_action=purpose_default,
                class_actions=class_actions,
                field_actions=field_actions,
            )
        rules.append(
            DatasetRule(
                rule_id=str(item.get("id") or item.get("match") or "dataset"),
                match=str(item.get("match", item.get("id", ""))),
                risk=str(item.get("risk", "UNKNOWN")),
                default_action=default_action,
                purposes=purposes,
            )
        )
    return DatasetPolicySet(tuple(rules))


def _matches(value: str, patterns: frozenset[str]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _mask(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bytes):
        if len(value) <= 4:
            return b"*" * len(value)
        return b"*" * (len(value) - 4) + value[-4:]
    text = str(value)
    if not text:
        return text
    if len(text) <= 4:
        return "*" * len(text)
    return "*" * (len(text) - 4) + text[-4:]


class EgressGate:
    """Purpose-bound selective disclosure for agent-visible structured results.

    The gate derives agent, purpose and scope from the active lease. Callers cannot
    widen authority by supplying those fields themselves.
    """

    RECEIPT_KIND = "privacy-receipt"
    REVEAL_BUDGET_KIND = "reveal-budget"

    def __init__(self, runtime: Any, policies: DatasetPolicySet) -> None:
        self.runtime = runtime
        self.policies = policies

    def _receipt(
        self,
        *,
        decision: ReceiptDecision,
        reason_code: str,
        path_coverage: str,
        dataset_id: str,
        rule: DatasetRule | None,
        surface: str,
        purpose: str,
        operation: str,
        destination: str,
        rows_observed: int,
        rows_released: int = 0,
        protected_values: int = 0,
        denied_values: int = 0,
        aggregate_only_values: int = 0,
        masked_values: int = 0,
        raw_values_released: int = 0,
        raw_sensitive_values_released: int = 0,
        unknown_fields: int = 0,
        classes: Sequence[DataClass] = (),
    ) -> PrivacyReceipt:
        receipt = PrivacyReceipt(
            receipt_id="BBMR-" + secrets.token_urlsafe(12),
            timestamp=datetime.now(UTC).isoformat(),
            decision=decision,
            reason_code=reason_code,
            path_coverage=path_coverage,
            dataset_id=dataset_id,
            dataset_rule=rule.rule_id if rule else None,
            risk=rule.risk if rule else None,
            surface=surface,
            purpose=purpose,
            operation=operation,
            destination=destination,
            rows_observed=rows_observed,
            rows_released=rows_released,
            protected_values=protected_values,
            denied_values=denied_values,
            aggregate_only_values=aggregate_only_values,
            masked_values=masked_values,
            raw_values_released=raw_values_released,
            raw_sensitive_values_released=raw_sensitive_values_released,
            unknown_fields=unknown_fields,
            data_classes_observed=tuple(sorted({item.value for item in classes})),
        )
        self.runtime.secure_state.put_json(self.RECEIPT_KIND, receipt.receipt_id, asdict(receipt))
        return receipt

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        return self.runtime.secure_state.get_json(self.RECEIPT_KIND, receipt_id)

    def _reserve_reveal_rows(
        self,
        *,
        lease_id: str,
        rule: DatasetRule,
        purpose: str,
        limit: int | None,
        rows: int,
    ) -> bool:
        """Atomically reserve lease-scoped raw-disclosure budget.

        The counter contains no business values and is owned by the lease so it is
        deleted with the lease. A rejected reservation does not consume budget.
        """
        if rows <= 0 or limit is None:
            return True
        key_material = f"{lease_id}\0{rule.rule_id}\0{purpose}".encode("utf-8")
        key = hashlib.sha256(key_material).hexdigest()
        with self.runtime.secure_state.transaction():
            current = self.runtime.secure_state.get_json(self.REVEAL_BUDGET_KIND, key) or {"used": 0}
            used = int(current.get("used", 0))
            if used + rows > limit:
                return False
            self.runtime.secure_state.put_json(
                self.REVEAL_BUDGET_KIND,
                key,
                {"used": used + rows, "limit": limit},
                owner=lease_id,
            )
        return True

    def protect_compiled_grid(
        self,
        records: Sequence[Mapping[str, Any]],
        lease_id: str,
        *,
        recipe: Any,
        surface: str = "GRID",
        path_verified: bool = True,
    ) -> EgressResult:
        """Enforce an already compiled privacy recipe.

        The recipe is bound to policy version, dataset, purpose, operation and
        destination. Unknown fields are denied rather than inferred on the hot path.
        """
        context = self.runtime.lease_context(lease_id)
        purpose = str(context["purpose"])
        agent_id = str(context["agent_id"])
        scope = str(context["scope"])
        if not path_verified:
            receipt = self._receipt(
                decision=ReceiptDecision.UNVERIFIED,
                reason_code="BBM_EGRESS_PATH_UNVERIFIED",
                path_coverage="UNVERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=self.policies.resolve(str(recipe.dataset_id)),
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)

        if purpose != str(recipe.purpose):
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_COMPILED_PURPOSE_MISMATCH",
                path_coverage="VERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=self.policies.resolve(str(recipe.dataset_id)),
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)

        if str(recipe.policy_version) != str(self.runtime.policy.version):
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_COMPILED_POLICY_STALE",
                path_coverage="VERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=self.policies.resolve(str(recipe.dataset_id)),
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)

        rule = self.policies.resolve(str(recipe.dataset_id))
        if rule is None:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_CLASSIFICATION_REQUIRED",
                path_coverage="VERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=None,
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)
        purpose_rule = rule.purposes.get(purpose)
        if purpose_rule is None:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_PURPOSE_DENIED",
                path_coverage="VERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=rule,
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)

        checks = (
            (_matches(str(recipe.operation), purpose_rule.operations), "BBM_DATASET_OPERATION_DENIED"),
            (_matches(str(recipe.destination), purpose_rule.destinations), "BBM_DATASET_DESTINATION_DENIED"),
            (_matches(agent_id, purpose_rule.agents), "BBM_DATASET_AGENT_DENIED"),
            (_matches(scope, purpose_rule.lease_scopes), "BBM_DATASET_SCOPE_DENIED"),
        )
        for allowed, code in checks:
            if not allowed:
                receipt = self._receipt(
                    decision=ReceiptDecision.BLOCKED,
                    reason_code=code,
                    path_coverage="VERIFIED",
                    dataset_id=str(recipe.dataset_id),
                    rule=rule,
                    surface=surface,
                    purpose=purpose,
                    operation=str(recipe.operation),
                    destination=str(recipe.destination),
                    rows_observed=len(records),
                )
                return EgressResult((), receipt)

        if purpose_rule.max_rows is not None and len(records) > purpose_rule.max_rows:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_ROW_LIMIT",
                path_coverage="VERIFIED",
                dataset_id=str(recipe.dataset_id),
                rule=rule,
                surface=surface,
                purpose=purpose,
                operation=str(recipe.operation),
                destination=str(recipe.destination),
                rows_observed=len(records),
            )
            return EgressResult((), receipt)

        recipe_fields = {item.field: item for item in recipe.fields}
        protected = denied = aggregate = masked = raw = raw_sensitive = unknown = 0
        classes_seen: list[DataClass] = []
        output: list[dict[str, Any]] = []

        for record in records:
            if not isinstance(record, Mapping):
                receipt = self._receipt(
                    decision=ReceiptDecision.BLOCKED,
                    reason_code="BBM_EGRESS_INVALID_STRUCTURE",
                    path_coverage="VERIFIED",
                    dataset_id=str(recipe.dataset_id),
                    rule=rule,
                    surface=surface,
                    purpose=purpose,
                    operation=str(recipe.operation),
                    destination=str(recipe.destination),
                    rows_observed=len(records),
                )
                return EgressResult((), receipt)

            out: dict[str, Any] = {}
            for field, value in record.items():
                compiled = recipe_fields.get(str(field))
                if compiled is None:
                    unknown += 1
                    denied += 1
                    continue
                data_class = compiled.data_class
                # A compiled recipe is an optimization, never an authority source.
                # Re-evaluate current dataset policy and enforce whichever decision is
                # stricter. This prevents a caller from fabricating or replaying a
                # permissive recipe object to widen disclosure.
                current_action = purpose_rule.action_for(str(field), data_class, rule.default_action)
                action = _stricter_action(compiled.action, current_action)
                classes_seen.append(data_class)

                if action is DisclosureAction.DENY:
                    denied += 1
                    continue
                if action is DisclosureAction.AGGREGATE:
                    aggregate += 1
                    continue
                if action is DisclosureAction.HANDLE:
                    if value is None or value == "":
                        out[field] = value
                    else:
                        out[field] = self.runtime.protect_value_as_handle(
                            value,
                            data_class,
                            lease_id,
                            origin_scope=f"DATASET:{recipe.dataset_id}",
                        )
                        protected += 1
                    continue
                if action is DisclosureAction.MASKED:
                    if data_class is DataClass.SECRET:
                        denied += 1
                        continue
                    out[field] = _mask(value)
                    masked += 1
                    continue
                if action is DisclosureAction.REVEAL:
                    if data_class is DataClass.SECRET:
                        denied += 1
                        continue
                    out[field] = value
                    if value is not None and value != "":
                        raw += 1
                        if data_class is not DataClass.PUBLIC:
                            raw_sensitive += 1
                    continue
                denied += 1
            output.append(out)

        disclosed = raw > 0 or masked > 0
        receipt = self._receipt(
            decision=(ReceiptDecision.AUTHORIZED_DISCLOSURE if disclosed else ReceiptDecision.VERIFIED_PROTECTED),
            reason_code=("BBM_EGRESS_AUTHORIZED_DISCLOSURE" if disclosed else "BBM_EGRESS_PROTECTED"),
            path_coverage="VERIFIED",
            dataset_id=str(recipe.dataset_id),
            rule=rule,
            surface=surface,
            purpose=purpose,
            operation=str(recipe.operation),
            destination=str(recipe.destination),
            rows_observed=len(records),
            rows_released=len(output),
            protected_values=protected,
            denied_values=denied,
            aggregate_only_values=aggregate,
            masked_values=masked,
            raw_values_released=raw,
            raw_sensitive_values_released=raw_sensitive,
            unknown_fields=unknown,
            classes=classes_seen,
        )
        return EgressResult(tuple(output), receipt)

    def protect_grid(
        self,
        records: Sequence[Mapping[str, Any]],
        schema: Mapping[str, DataClass | str],
        lease_id: str,
        *,
        dataset_id: str,
        operation: str,
        destination: str,
        surface: str = "GRID",
        path_verified: bool = True,
    ) -> EgressResult:
        context = self.runtime.lease_context(lease_id)
        purpose = str(context["purpose"])
        agent_id = str(context["agent_id"])
        scope = str(context["scope"])
        rows_observed = len(records)

        if not path_verified:
            receipt = self._receipt(
                decision=ReceiptDecision.UNVERIFIED,
                reason_code="BBM_EGRESS_PATH_UNVERIFIED",
                path_coverage="UNVERIFIED",
                dataset_id=dataset_id,
                rule=None,
                surface=surface,
                purpose=purpose,
                operation=operation,
                destination=destination,
                rows_observed=rows_observed,
            )
            return EgressResult((), receipt)

        if any(not isinstance(record, Mapping) for record in records):
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_EGRESS_INVALID_STRUCTURE",
                path_coverage="VERIFIED",
                dataset_id=dataset_id,
                rule=None,
                surface=surface,
                purpose=purpose,
                operation=operation,
                destination=destination,
                rows_observed=rows_observed,
            )
            return EgressResult((), receipt)

        rule = self.policies.resolve(dataset_id)
        if rule is None:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_CLASSIFICATION_REQUIRED",
                path_coverage="VERIFIED",
                dataset_id=dataset_id,
                rule=None,
                surface=surface,
                purpose=purpose,
                operation=operation,
                destination=destination,
                rows_observed=rows_observed,
            )
            return EgressResult((), receipt)

        purpose_rule = rule.purposes.get(purpose)
        if purpose_rule is None:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_PURPOSE_DENIED",
                path_coverage="VERIFIED",
                dataset_id=dataset_id,
                rule=rule,
                surface=surface,
                purpose=purpose,
                operation=operation,
                destination=destination,
                rows_observed=rows_observed,
            )
            return EgressResult((), receipt)

        checks = (
            (_matches(operation, purpose_rule.operations), "BBM_DATASET_OPERATION_DENIED"),
            (_matches(destination, purpose_rule.destinations), "BBM_DATASET_DESTINATION_DENIED"),
            (_matches(agent_id, purpose_rule.agents), "BBM_DATASET_AGENT_DENIED"),
            (_matches(scope, purpose_rule.lease_scopes), "BBM_DATASET_SCOPE_DENIED"),
        )
        for allowed, code in checks:
            if not allowed:
                receipt = self._receipt(
                    decision=ReceiptDecision.BLOCKED,
                    reason_code=code,
                    path_coverage="VERIFIED",
                    dataset_id=dataset_id,
                    rule=rule,
                    surface=surface,
                    purpose=purpose,
                    operation=operation,
                    destination=destination,
                    rows_observed=rows_observed,
                )
                return EgressResult((), receipt)

        if purpose_rule.max_rows is not None and rows_observed > purpose_rule.max_rows:
            receipt = self._receipt(
                decision=ReceiptDecision.BLOCKED,
                reason_code="BBM_DATASET_ROW_LIMIT",
                path_coverage="VERIFIED",
                dataset_id=dataset_id,
                rule=rule,
                surface=surface,
                purpose=purpose,
                operation=operation,
                destination=destination,
                rows_observed=rows_observed,
            )
            return EgressResult((), receipt)

        protected = denied = aggregate = masked = raw = raw_sensitive = unknown = 0
        classes_seen: list[DataClass] = []
        output: list[dict[str, Any]] = []

        for record in records:
            out: dict[str, Any] = {}
            for field, value in record.items():
                declared = schema.get(field, DataClass.UNKNOWN)
                data_class = declared if isinstance(declared, DataClass) else DataClass(str(declared))
                classes_seen.append(data_class)
                if field not in schema:
                    unknown += 1
                action = purpose_rule.action_for(field, data_class, rule.default_action)

                if action is DisclosureAction.DENY:
                    denied += 1
                    continue
                if action is DisclosureAction.AGGREGATE:
                    aggregate += 1
                    continue
                if action is DisclosureAction.HANDLE:
                    if value is None or value == "":
                        out[field] = value
                    else:
                        out[field] = self.runtime.protect_value_as_handle(
                            value,
                            data_class,
                            lease_id,
                            origin_scope=f"DATASET:{dataset_id}",
                        )
                        protected += 1
                    continue
                if action is DisclosureAction.MASKED:
                    if data_class is DataClass.SECRET:
                        denied += 1
                        continue
                    out[field] = _mask(value)
                    masked += 1
                    continue
                if action is DisclosureAction.REVEAL:
                    if data_class is DataClass.SECRET:
                        denied += 1
                        continue
                    out[field] = value
                    if value is not None and value != "":
                        raw += 1
                        if data_class is not DataClass.PUBLIC:
                            raw_sensitive += 1
                    continue
                denied += 1
            output.append(out)

        disclosed = raw > 0 or masked > 0
        receipt = self._receipt(
            decision=(ReceiptDecision.AUTHORIZED_DISCLOSURE if disclosed else ReceiptDecision.VERIFIED_PROTECTED),
            reason_code=("BBM_EGRESS_AUTHORIZED_DISCLOSURE" if disclosed else "BBM_EGRESS_PROTECTED"),
            path_coverage="VERIFIED",
            dataset_id=dataset_id,
            rule=rule,
            surface=surface,
            purpose=purpose,
            operation=operation,
            destination=destination,
            rows_observed=rows_observed,
            rows_released=len(output),
            protected_values=protected,
            denied_values=denied,
            aggregate_only_values=aggregate,
            masked_values=masked,
            raw_values_released=raw,
            raw_sensitive_values_released=raw_sensitive,
            unknown_fields=unknown,
            classes=classes_seen,
        )
        return EgressResult(tuple(output), receipt)
