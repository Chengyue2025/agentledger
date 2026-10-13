"""防篡改责任留痕账本。

为什么需要它：
  监管问询/客户审计真正要的不是"一份报告"，而是
  **"这条结论在什么时间、基于哪一版代码、由谁确认"**。
  纯文件可以随手改，链式哈希不能。

结构（JSONL，每行一条）：
  seq        序号
  ts         UTC 时间戳
  tool       工具版本
  target     被扫描目标
  findings   发现项数量
  digest     发现项内容摘要（sha256）
  merkle     发现项 Merkle 根
  prev       上一条的 hash
  hash       本条的 hash = sha256(canonical(entry - hash))

任何一条被修改/删除/插入，其后所有 hash 都会失配 —— 这正是我们要的性质。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import TOOL_ID
from .model import Finding

GENESIS = "0" * 64
LEDGER_DIRNAME = ".agentledger"
LEDGER_FILENAME = "ledger.jsonl"


# --------------------------------------------------------------------------
def canonical(obj: Any) -> str:
    """确定性 JSON 序列化 —— 哈希的前提。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def finding_digest(f: Finding) -> str:
    return sha256_hex(canonical(f.to_dict()))


def merkle_root(items: Iterable[str]) -> str:
    """标准 Merkle 根。空集合返回空串哈希，避免与"全零"混淆。"""
    level = [sha256_hex(i) for i in items]
    if not level:
        return sha256_hex("[]")
    level = [sha256_hex(x) for x in level]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def findings_merkle(findings: list[Finding]) -> str:
    """按排序键计算，保证与发现项输出顺序无关。"""
    ordered = sorted(findings, key=lambda f: f.sort_key())
    return merkle_root(finding_digest(f) for f in ordered)


# --------------------------------------------------------------------------
@dataclass
class LedgerEntry:
    seq: int
    ts: str
    tool: str
    target: str
    findings: int
    digest: str
    merkle: str
    prev: str
    hash: str

    def payload(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "tool": self.tool,
            "target": self.target, "findings": self.findings,
            "digest": self.digest, "merkle": self.merkle, "prev": self.prev,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["hash"] = self.hash
        return d

    @staticmethod
    def compute_hash(payload: dict[str, Any]) -> str:
        return sha256_hex(canonical(payload))

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "LedgerEntry":
        return LedgerEntry(
            seq=d["seq"], ts=d["ts"], tool=d["tool"], target=d["target"],
            findings=d["findings"], digest=d["digest"], merkle=d["merkle"],
            prev=d["prev"], hash=d["hash"],
        )


class Ledger:
    """追加式账本。文件位于 <root>/.agentledger/ledger.jsonl"""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # ------------------------------------------------------------------
    @classmethod
    def for_root(cls, root: str | Path) -> "Ledger":
        return cls(Path(root) / LEDGER_DIRNAME / LEDGER_FILENAME)

    # ------------------------------------------------------------------
    def entries(self) -> list[LedgerEntry]:
        if not self.path.exists():
            return []
        out: list[LedgerEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(LedgerEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError):
                out.append(LedgerEntry(
                    seq=-1, ts="", tool="", target="", findings=0,
                    digest="", merkle="", prev="", hash="<unparsable>"))
        return out

    def head(self) -> str:
        ents = self.entries()
        return ents[-1].hash if ents else GENESIS

    # ------------------------------------------------------------------
    def append(self, target: str, findings: list[Finding],
               ts: str | None = None) -> LedgerEntry:
        ents = self.entries()
        prev_hash = ents[-1].hash if ents else GENESIS
        seq = (ents[-1].seq + 1) if ents and ents[-1].seq >= 0 else 0

        ordered = sorted(findings, key=lambda f: f.sort_key())
        payload = {
            "seq": seq,
            "ts": ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": TOOL_ID,
            "target": target,
            "findings": len(ordered),
            "digest": merkle_root(finding_digest(f) for f in ordered),
            "merkle": merkle_root(finding_digest(f) for f in ordered),
            "prev": prev_hash,
        }
        entry = LedgerEntry(**payload, hash=LedgerEntry.compute_hash(payload))

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical(entry.to_dict()) + "\n")
        return entry

    # ------------------------------------------------------------------
    def verify(self) -> tuple[bool, list[str]]:
        """校验整条链。返回 (是否完好, 问题列表)。"""
        problems: list[str] = []
        ents = self.entries()
        if not ents:
            return True, []

        expected_prev = GENESIS
        for i, e in enumerate(ents):
            if e.hash == "<unparsable>":
                problems.append(f"[{i}] 该行无法解析为账本条目（可能被手工编辑）")
                continue
            if e.prev != expected_prev:
                problems.append(
                    f"[{i}] 链断裂：prev={e.prev[:16]}… 期望 {expected_prev[:16]}…"
                    f"（前序条目被删除或改写）")
            recomputed = LedgerEntry.compute_hash(e.payload())
            if recomputed != e.hash:
                problems.append(
                    f"[{i}] 哈希不匹配：记录 {e.hash[:16]}… 重算 {recomputed[:16]}…"
                    f"（本条目内容被修改）")
            expected_prev = e.hash
        return not problems, problems

    # ------------------------------------------------------------------
    def export(self) -> dict[str, Any]:
        ents = self.entries()
        return {
            "ledger_path": str(self.path),
            "entries": [e.to_dict() for e in ents],
            "head": self.head(),
            "verified": self.verify()[0],
        }


# --------------------------------------------------------------------------
# 人工签署（机器出证据，人签字 —— 这是本工具唯一不可自动化的一环）
# --------------------------------------------------------------------------
def attest(payload: Any, key: bytes | str) -> str:
    """HMAC-SHA256 分离式签名。

    注意：HMAC 是对称算法 —— 持有同一把 key 的人都能产出相同签名。
    它保证的是"证据未被第三方改动"，不是"某个具体的人签的"。
    若需不可抵赖的非对称签名，请用外部 KMS/CA 签发后附加到证据包。
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_attestation(payload: Any, key: bytes | str, signature: str) -> bool:
    return hmac.compare_digest(attest(payload, key), signature)


def generate_key() -> str:
    return secrets.token_hex(32)


def write_key(path: str | Path, key: str | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists() and not key:
        return p
    p.write_text(key or generate_key(), encoding="ascii")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass  # Windows 上不支持 POSIX 权限位，忽略
    return p