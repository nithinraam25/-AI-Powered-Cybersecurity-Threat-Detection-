"""Deterministic security rule definitions and heuristic configurations.

Provides configurable, interpretable heuristic security rules operating on
the 41 canonical NSL-KDD network traffic features.

Important Note:
All thresholds defined herein represent initial operational heuristics for
triage and anomaly detection, not empirically validated universal constants.
A rule match indicates that observed flow telemetry matches a suspicious
structural pattern; it does not constitute proof of confirmed malicious compromise.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Union
import pandas as pd


@dataclass
class RuleMatch:
    """Structured representation of a single security rule match."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    matched_fields: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary."""
        return asdict(self)


@dataclass
class LandRuleConfig:
    """Configuration for self-referential LAND topology anomaly rule."""

    severity: str = "HIGH"


@dataclass
class SynFloodRuleConfig:
    """Configuration for high-volume SYN error rate rule."""

    count_threshold: int = 100
    serror_rate_threshold: float = 0.80
    target_flags: Set[str] = field(
        default_factory=lambda: {"S0", "S1", "S2", "S3", "RSTOS0"}
    )
    severity: str = "MEDIUM"


@dataclass
class RejectionBurstRuleConfig:
    """Configuration for connection rejection burst rule."""

    count_threshold: int = 50
    rerror_rate_threshold: float = 0.80
    target_flags: Set[str] = field(
        default_factory=lambda: {"REJ", "RSTO", "RSTR"}
    )
    severity: str = "MEDIUM"


@dataclass
class PortScanRuleConfig:
    """Configuration for multi-service probe and port sweep rule."""

    count_threshold: int = 50
    diff_srv_rate_threshold: float = 0.70
    dst_host_diff_srv_rate_threshold: float = 0.70
    severity: str = "MEDIUM"


@dataclass
class SecurityRulesConfig:
    """Aggregated configuration for all security heuristic rules."""

    land_config: LandRuleConfig = field(default_factory=LandRuleConfig)
    syn_flood_config: SynFloodRuleConfig = field(default_factory=SynFloodRuleConfig)
    rej_burst_config: RejectionBurstRuleConfig = field(default_factory=RejectionBurstRuleConfig)
    port_scan_config: PortScanRuleConfig = field(default_factory=PortScanRuleConfig)


class BaseSecurityRule(ABC):
    """Abstract base class for deterministic security rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for the security rule."""
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name of the security rule."""
        pass

    @abstractmethod
    def evaluate(self, record: Union[Dict[str, Any], pd.Series]) -> Optional[RuleMatch]:
        """Evaluate a single traffic record against the rule condition.

        Args:
            record: Dictionary or pd.Series mapping feature names to values.

        Returns:
            RuleMatch if condition is satisfied, None otherwise.
        """
        pass


class LandAttackRule(BaseSecurityRule):
    """Rule detecting self-referential network connection topology (LAND attack).

    Trigger Condition:
        land == 1 (Source IP and port match destination IP and port).
    """

    def __init__(self, config: Optional[LandRuleConfig] = None) -> None:
        self.config = config or LandRuleConfig()

    @property
    def rule_id(self) -> str:
        return "RULE-LAND-001"

    @property
    def rule_name(self) -> str:
        return "Self-Referential Address Topology Anomaly (LAND)"

    def evaluate(self, record: Union[Dict[str, Any], pd.Series]) -> Optional[RuleMatch]:
        try:
            land_val = int(record["land"])
        except (KeyError, TypeError, ValueError):
            return None

        if land_val == 1:
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.config.severity,
                description=(
                    "Connection indicates self-referential addressing where source "
                    "matches destination (land=1). This pattern matches the classic "
                    "LAND denial-of-service condition."
                ),
                matched_fields={"land": land_val},
            )
        return None


class SynFloodHeuristicRule(BaseSecurityRule):
    """Rule detecting high-volume unestablished SYN error state bursts.

    Trigger Condition:
        count >= count_threshold (default: 100)
        AND serror_rate >= serror_rate_threshold (default: 0.80)
        AND flag in target_flags (default: {'S0', 'S1', 'S2', 'S3', 'RSTOS0'})
    """

    def __init__(self, config: Optional[SynFloodRuleConfig] = None) -> None:
        self.config = config or SynFloodRuleConfig()

    @property
    def rule_id(self) -> str:
        return "RULE-DOS-SYN-001"

    @property
    def rule_name(self) -> str:
        return "High-Volume SYN Error State Heuristic"

    def evaluate(self, record: Union[Dict[str, Any], pd.Series]) -> Optional[RuleMatch]:
        try:
            count_val = int(record["count"])
            serror_val = float(record["serror_rate"])
            flag_val = str(record["flag"]).strip().upper()
        except (KeyError, TypeError, ValueError):
            return None

        target_flags_upper = {f.upper() for f in self.config.target_flags}
        if (
            count_val >= self.config.count_threshold
            and serror_val >= self.config.serror_rate_threshold
            and flag_val in target_flags_upper
        ):
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.config.severity,
                description=(
                    f"Elevated connection volume ({count_val} >= {self.config.count_threshold}) "
                    f"with high SYN error rate ({serror_val:.2f} >= {self.config.serror_rate_threshold:.2f}) "
                    f"and unestablished state flag '{flag_val}'. Pattern matches SYN flood telemetry."
                ),
                matched_fields={
                    "count": count_val,
                    "serror_rate": serror_val,
                    "flag": flag_val,
                },
            )
        return None


class ConnectionRejectionBurstRule(BaseSecurityRule):
    """Rule detecting high-volume connection rejection bursts.

    Trigger Condition:
        count >= count_threshold (default: 50)
        AND rerror_rate >= rerror_rate_threshold (default: 0.80)
        AND flag in target_flags (default: {'REJ', 'RSTO', 'RSTR'})
    """

    def __init__(self, config: Optional[RejectionBurstRuleConfig] = None) -> None:
        self.config = config or RejectionBurstRuleConfig()

    @property
    def rule_id(self) -> str:
        return "RULE-DOS-REJ-001"

    @property
    def rule_name(self) -> str:
        return "High-Volume Connection Rejection Burst Heuristic"

    def evaluate(self, record: Union[Dict[str, Any], pd.Series]) -> Optional[RuleMatch]:
        try:
            count_val = int(record["count"])
            rerror_val = float(record["rerror_rate"])
            flag_val = str(record["flag"]).strip().upper()
        except (KeyError, TypeError, ValueError):
            return None

        target_flags_upper = {f.upper() for f in self.config.target_flags}
        if (
            count_val >= self.config.count_threshold
            and rerror_val >= self.config.rerror_rate_threshold
            and flag_val in target_flags_upper
        ):
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.config.severity,
                description=(
                    f"Elevated connection volume ({count_val} >= {self.config.count_threshold}) "
                    f"with high rejection rate ({rerror_val:.2f} >= {self.config.rerror_rate_threshold:.2f}) "
                    f"and rejection state flag '{flag_val}'. Pattern matches repeated closed-port hammering."
                ),
                matched_fields={
                    "count": count_val,
                    "rerror_rate": rerror_val,
                    "flag": flag_val,
                },
            )
        return None


class MultiServicePortSweepRule(BaseSecurityRule):
    """Rule detecting multi-service probe and port sweep patterns.

    Trigger Condition:
        count >= count_threshold (default: 50)
        AND diff_srv_rate >= diff_srv_rate_threshold (default: 0.70)
        AND dst_host_diff_srv_rate >= dst_host_diff_srv_rate_threshold (default: 0.70)
    """

    def __init__(self, config: Optional[PortScanRuleConfig] = None) -> None:
        self.config = config or PortScanRuleConfig()

    @property
    def rule_id(self) -> str:
        return "RULE-PROBE-SCAN-001"

    @property
    def rule_name(self) -> str:
        return "Multi-Service Port Sweep & Probe Heuristic"

    def evaluate(self, record: Union[Dict[str, Any], pd.Series]) -> Optional[RuleMatch]:
        try:
            count_val = int(record["count"])
            diff_srv_val = float(record["diff_srv_rate"])
            dst_diff_srv_val = float(record["dst_host_diff_srv_rate"])
        except (KeyError, TypeError, ValueError):
            return None

        if (
            count_val >= self.config.count_threshold
            and diff_srv_val >= self.config.diff_srv_rate_threshold
            and dst_diff_srv_val >= self.config.dst_host_diff_srv_rate_threshold
        ):
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.config.severity,
                description=(
                    f"Connection burst ({count_val} >= {self.config.count_threshold}) spanning "
                    f"multiple target services (diff_srv_rate={diff_srv_val:.2f} >= {self.config.diff_srv_rate_threshold:.2f}, "
                    f"dst_host_diff_srv_rate={dst_diff_srv_val:.2f} >= {self.config.dst_host_diff_srv_rate_threshold:.2f}). "
                    "Pattern matches horizontal or vertical port scanning."
                ),
                matched_fields={
                    "count": count_val,
                    "diff_srv_rate": diff_srv_val,
                    "dst_host_diff_srv_rate": dst_diff_srv_val,
                },
            )
        return None


def create_default_security_rules(
    config: Optional[SecurityRulesConfig] = None,
) -> List[BaseSecurityRule]:
    """Instantiate the default suite of deterministic security heuristic rules."""
    cfg = config or SecurityRulesConfig()
    return [
        LandAttackRule(cfg.land_config),
        SynFloodHeuristicRule(cfg.syn_flood_config),
        ConnectionRejectionBurstRule(cfg.rej_burst_config),
        MultiServicePortSweepRule(cfg.port_scan_config),
    ]
