"""流水线各层共用的数据模型：候选、分诊结论、验证结论、最终发现。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Literal

Verdict = Literal["confirmed", "false_positive", "inconclusive"]
Confidence = Literal["high", "medium", "low"]


def asdict_jsonable(obj: Any) -> Any:
    """dataclass（含嵌套）→ 可直接 json.dumps 的 dict/list。"""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: asdict_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [asdict_jsonable(v) for v in obj]
    return obj

# v1 漏洞类别注册表（唯一事实源）：类别 → (CWE, check_id 匹配片段)。
# 新增/调整类别只改这里；KNOWN_CATEGORIES、CWE 反查、规则推断均由此派生。
VULN_CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "sql_injection": ("CWE-89", ("sql-injection", "sqli", "insecure-sql-query",
                                  "tainted-sql-string")),
    "ssrf": ("CWE-918", ("ssrf", "request-forgery")),
    "path_traversal": ("CWE-22", ("path-traversal", "traversal")),
    # v2 扩展（check_id 片段自 pygoat 真实 semgrep 输出归纳）
    "command_injection": ("CWE-78", ("command-injection", "os-command-injection",
                                      "subprocess-injection", "subprocess-shell-true",
                                      "dangerous-subprocess-use")),
    "xss": ("CWE-79", ("xss", "cross-site-scripting")),
    "ssti": ("CWE-1336", ("ssti", "server-side-template-injection")),
    "code_injection": ("CWE-94", ("user-eval", "eval-detected")),
    "deserialization": ("CWE-502", ("pickle", "deserialization",
                                     "insecure-deserialization")),
}

CWE_TO_CATEGORY: dict[str, str] = {
    cwe: category for category, (cwe, _) in VULN_CATEGORIES.items()
}


def normalize_cwe(raw: object) -> str | None:
    """semgrep metadata 里 cwe 形态多样：'CWE-89: ...'、['CWE-89']、'89' → 统一 'CWE-89'。"""
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if not isinstance(raw, str) or not raw.strip():
        return None
    token = raw.split(":")[0].strip().upper()
    digits = token[4:] if token.startswith("CWE-") else token
    return f"CWE-{digits}" if digits.isdigit() else None


def infer_cwe(check_id: str) -> str | None:
    low = check_id.lower()
    for cwe, fragments in VULN_CATEGORIES.values():
        if any(fragment in low for fragment in fragments):
            return cwe
    return None


def infer_category(check_id: str, cwe: str | None) -> str:
    if cwe and cwe in CWE_TO_CATEGORY:
        return CWE_TO_CATEGORY[cwe]
    low = check_id.lower()
    for category, (_, fragments) in VULN_CATEGORIES.items():
        if any(fragment in low for fragment in fragments):
            return category
    return "unknown"


@dataclass
class Candidate:
    """第一层（semgrep）产出的候选：可能为真也可能为假的漏洞位点。"""

    check_id: str
    path: str  # 相对目标仓库根
    start_line: int
    end_line: int
    snippet: str
    message: str
    cwe: str | None = None
    category: str = "unknown"
    source: str = "semgrep"

    @property
    def location(self) -> str:
        return f"{self.path}:{self.start_line}"


@dataclass
class TriageResult:
    """第二层（便宜 LLM）结论：keep/drop + 一行理由。"""

    keep: bool
    reason: str
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0


@dataclass
class Verification:
    """第三层（codex exec）结论：输出契约的结构化结果。"""

    verdict: Verdict
    cwe: str
    taint_path: list[str] = field(default_factory=list)
    confidence: Confidence = "medium"
    poc_idea: str = ""
    explanation: str = ""
    # 动态 PoC 请求规格（扁平，空串=不适用），由 DynamicValidator 执行
    poc_method: str = ""
    poc_path: str = ""
    poc_query: str = ""
    poc_body: str = ""
    poc_signal: str = ""
    error: str | None = None  # 非 None 表示验证过程本身出错（verdict 为 inconclusive）
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0


@dataclass
class Finding:
    """一个候选穿过漏斗后的全轨迹：报告与评测的最小单元。"""

    candidate: Candidate
    triage: TriageResult | None = None
    verification: Verification | None = None

    @property
    def status(self) -> str:
        if self.verification is not None:
            if self.verification.error:
                return "error"
            return "verified"
        if self.triage is not None:
            return "kept_at_triage" if self.triage.keep else "dropped_at_triage"
        return "candidate"

    @property
    def is_confirmed(self) -> bool:
        return self.verification is not None and self.verification.verdict == "confirmed"

    @property
    def is_false_positive(self) -> bool:
        return self.verification is not None and self.verification.verdict == "false_positive"

    @property
    def is_inconclusive(self) -> bool:
        return self.verification is not None and self.verification.verdict == "inconclusive"

    @property
    def is_kept(self) -> bool:
        """漏斗到「分诊后仍存活」口径：未分诊算存活（semgrep-only 模式），分诊后 drop 不算。"""
        return self.triage is None or self.triage.keep


@dataclass
class LayerStats:
    """漏斗分层统计：报告摘要与评测四指标的数据源。"""

    candidates: int = 0
    kept: int = 0
    dropped: int = 0
    confirmed: int = 0
    false_positives: int = 0
    inconclusive: int = 0
    errors: int = 0
    triage_tokens_in: int = 0
    triage_tokens_out: int = 0
    verify_tokens_in: int = 0
    verify_tokens_out: int = 0
    semgrep_seconds: float = 0.0
    triage_seconds: float = 0.0
    verify_seconds: float = 0.0

    @property
    def tokens_total(self) -> int:
        return (
            self.triage_tokens_in + self.triage_tokens_out
            + self.verify_tokens_in + self.verify_tokens_out
        )


@dataclass
class ScanReport:
    """一次扫描的完整产物：全部候选的漏斗轨迹 + 分层统计。"""

    target: str
    findings: list[Finding] = field(default_factory=list)
    truncated: int = 0  # --max-candidates 截断掉的候选数
    created_at: str = ""
    semgrep_seconds: float = 0.0
    triage_seconds: float = 0.0
    verify_seconds: float = 0.0

    def stats(self) -> LayerStats:
        s = LayerStats(candidates=len(self.findings))
        s.semgrep_seconds = self.semgrep_seconds
        s.triage_seconds = self.triage_seconds
        s.verify_seconds = self.verify_seconds
        for f in self.findings:
            if f.triage is not None:
                if f.triage.keep:
                    s.kept += 1
                else:
                    s.dropped += 1
                s.triage_tokens_in += f.triage.tokens_in
                s.triage_tokens_out += f.triage.tokens_out
            if f.verification is not None:
                v = f.verification
                if v.verdict == "confirmed":
                    s.confirmed += 1
                elif v.verdict == "false_positive":
                    s.false_positives += 1
                else:
                    s.inconclusive += 1
                if v.error:
                    s.errors += 1
                s.verify_tokens_in += v.tokens_in
                s.verify_tokens_out += v.tokens_out
        return s
