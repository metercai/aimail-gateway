#!/usr/bin/env python3
"""生成 DID-SIGNATURE-PROTOCOL.md 的字节向量（唯一事实源）。

用法：
    python3 protocol/vectors/gen_did_vectors.py                 # 写 protocol/vectors/did-signature.json
    python3 protocol/vectors/gen_did_vectors.py <out.json>       # 写指定路径（aimail 仓镜像用）

约束：
- 输出必须**确定性**：不写时间戳、不用随机数；固定 seed 派生 did:key。
- 改动任何字节布局时，必须同时改 protocol/DID-SIGNATURE-PROTOCOL.md，并重跑本脚本。
- 依赖：Python ≥ 3.9 标准库（hashlib 自带 sha256 与 blake2b）+ `cryptography`（Ed25519）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from typing import Any, Dict, List, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── 协议常量（与 DID-SIGNATURE-PROTOCOL.md §2 一致）────────────────────────
HEADER_NAME = "DID-Signature"
RESULTS_HEADER_NAME = "DID-Auth-Results"
SYSTEM_MAIL_HEADER = "X-AIMail-System"
PROTOCOL_VERSION = "1"
SIGNING_TAG = "DID-Signature-v1"
CONTENT_TAG = "Content-v1"
EMAIL_BINDING_TAG = "EmailBinding-v1"
DOMAIN_CONTROL_TAG = "DomainControl-v1"
BODY_HASH_PREFIX = "sha256:"
ANCHOR_HASH_PREFIX = "blake2b:"
ANCHOR_REF_PREFIX = "chain:"
ATTACHMENT_SEPARATOR = "\t"

ERRORS = [
    "did_absent",
    "did_unsupported",
    "signature_invalid",
    "body_hash_mismatch",
    "rcpt_hash_mismatch",
    "timestamp_out_of_window",
    "anchor_not_found",
    "anchor_type_mismatch",
    "anchor_hash_mismatch",
    "anchor_revoked",
    "anchor_expired",
    "chain_unavailable",
    "attachment_fetch_failed",
    "not_verifiable",
]

# ── base58btc（did:key 用）──────────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = 0
    for byte in raw:
        if byte:
            break
        pad += 1
    return "1" * pad + out


def did_key(public_key: bytes) -> str:
    # multicodec ed25519-pub = 0xed 0x01
    return "did:key:z" + b58encode(b"\xed\x01" + public_key)


# ── 摘要 ───────────────────────────────────────────────────────────────────
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blake2b256_hex(data: bytes) -> str:
    # BLAKE2b-256 是「摘要长度为 32」的参数化，不是 512 截断
    return hashlib.blake2b(data, digest_size=32).hexdigest()


# ── 正文规范化（协议 §4.2）─────────────────────────────────────────────────
def canon_body(body: Any) -> bytes:
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    lines = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    lines = [line.rstrip(b" \t") for line in lines]
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return b""
    return b"\n".join(lines) + b"\n"


def body_hash(body: Any) -> str:
    return BODY_HASH_PREFIX + sha256_hex(canon_body(body))


# ── 收件人哈希（协议 §4.3）─────────────────────────────────────────────────
def normalize_rcpt(addr: str) -> str:
    text = addr.strip()
    if not text:
        return ""
    if text.endswith(")") and "(" in text:
        text = text[: text.rindex("(")].strip()
    if "<" in text and ">" in text:
        start, end = text.rindex("<"), text.rindex(">")
        if end > start:
            text = text[start + 1 : end]
    return text.strip().lower()


def rcpt_hash(rcpts: Sequence[str]) -> str:
    normalized = [n for n in (normalize_rcpt(r) for r in rcpts) if n]
    normalized.sort()
    return BODY_HASH_PREFIX + sha256_hex("\n".join(normalized).encode("utf-8"))


# ── Content-v1 投影（协议 §4.1）────────────────────────────────────────────
def file_hash(data: bytes) -> str:
    return BODY_HASH_PREFIX + sha256_hex(data)


def name_hash(name: str) -> str:
    return BODY_HASH_PREFIX + sha256_hex(name.encode("utf-8"))


def content_v1(subject: str, body: Any, attachments: Sequence[Dict[str, Any]]) -> bytes:
    lines: List[str] = [
        CONTENT_TAG,
        subject.rstrip(),
        body_hash(body),
        str(len(attachments)),
    ]
    for index, att in enumerate(attachments, start=1):
        raw = bytes.fromhex(att.get("bytes_hex", ""))
        lines.append(
            "{i}{sep}{nh}{sep}{fh}".format(
                i=index,
                sep=ATTACHMENT_SEPARATOR,
                nh=name_hash(att["name"]),
                fh=file_hash(raw),
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


# ── 签名对象（协议 §4.4：七行，每行尾随 \n，含末行）───────────────────────
def signing_input(did: str, sender: str, timestamp: int, anchor_ref: str, bh: str, rh: str) -> bytes:
    return (
        "{tag}\n{did}\n{from_}\n{t}\n{vc}\n{bh}\n{rh}\n".format(
            tag=SIGNING_TAG, did=did, from_=sender, t=timestamp, vc=anchor_ref, bh=bh, rh=rh
        )
    ).encode("utf-8")


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def format_header(fields: Dict[str, str]) -> str:
    return "; ".join(
        [
            "v=" + fields["v"],
            'did="%s"' % fields["did"],
            "t=" + fields["t"],
            "s=" + fields["s"],
            'vc="%s"' % fields["vc"],
            'bh="%s"' % fields["bh"],
            'rh="%s"' % fields["rh"],
        ]
    )


# ── EmailBinding 锚点载荷（协议 §5：BLAKE2b，四行）────────────────────────
def payload_hash_email_binding(did: str, email: str, issuer_did: str) -> str:
    preimage = "{tag}\n{did}\n{email}\n{issuer}\n".format(
        tag=EMAIL_BINDING_TAG, did=did, email=email, issuer=issuer_did
    )
    return ANCHOR_HASH_PREFIX + blake2b256_hex(preimage.encode("utf-8"))


def payload_hash_domain_control(domain: str, issuer_did: str) -> str:
    preimage = "{tag}\n{domain}\n{issuer}\n".format(
        tag=DOMAIN_CONTROL_TAG, domain=domain, issuer=issuer_did
    )
    return ANCHOR_HASH_PREFIX + blake2b256_hex(preimage.encode("utf-8"))


# ── 生成 ───────────────────────────────────────────────────────────────────
def build() -> Dict[str, Any]:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    did = did_key(public)

    subject = "Q3 report"
    body = "Hello Alice,\r\n\r\n    this is   a test.  \r\n\r\n\r\n"
    rcpts = ["Bob <Bob@Example.com>", "alice@example.com"]
    timestamp = 1765144656
    anchor_ref = ANCHOR_REF_PREFIX + "anchor-abc123"
    issuer = "did:web:issuer.example.com"

    bh = body_hash(body)
    rh = rcpt_hash(rcpts)
    message = signing_input(did, "alice@example.com", timestamp, anchor_ref, bh, rh)
    signature = private.sign(message)
    header = format_header(
        {
            "v": PROTOCOL_VERSION,
            "did": did,
            "t": str(timestamp),
            "s": b64url_nopad(signature),
            "vc": anchor_ref,
            "bh": bh,
            "rh": rh,
        }
    )

    att_doc = {"name": "q3.pdf", "bytes_hex": b"%PDF-1.4 hello".hex()}
    att_second = {"name": "notes.txt", "bytes_hex": b"line1\nline2\n".hex()}
    att_hostile = {"name": "a\x00b\nc.txt", "bytes_hex": b"x".hex()}

    content_cases = [
        {"case": "plain-no-attachment", "subject": subject, "body": body, "attachments": []},
        {"case": "two-attachments", "subject": subject, "body": body,
         "attachments": [att_doc, att_second]},
        {"case": "hostile-filename", "subject": "t", "body": "x", "attachments": [att_hostile]},
        {"case": "empty-body", "subject": "", "body": "", "attachments": []},
        {"case": "trailing-space-and-crlf", "subject": "  padded subject  ",
         "body": "a\t\r\nb   \r\n\r\n", "attachments": []},
    ]
    for case in content_cases:
        case["body_hash"] = body_hash(case["body"])
        case["bytes_hex"] = content_v1(case["subject"], case["body"], case["attachments"]).hex()

    rcpt_cases = [
        {"case": "header-main-set", "rcpts": rcpts},
        {"case": "single", "rcpts": ["alice@example.com"]},
        {"case": "sorted-not-input-order", "rcpts": ["zoe@x.com", "amy@x.com", "Bob <bob@x.com>"]},
        {"case": "display-name-and-comment", "rcpts": ["Bob <Bob@X.com> (work)"]},
        {"case": "mixed-case-dedup-not-applied", "rcpts": ["A@X.com", "a@x.com"]},
        {"case": "empty", "rcpts": []},
    ]
    for case in rcpt_cases:
        case["hex"] = rcpt_hash(case["rcpts"])
    # 自检：头里的 rh / bh 必须与向量同源（同一来源，不许二次计算）
    assert rcpt_cases[0]["hex"] == rh, "header rh 与向量不同源"
    assert content_cases[0]["body_hash"] == bh, "header bh 与向量不同源"

    signing_cases = [
        {"case": "main", "did": did, "from": "alice@example.com", "t": timestamp,
         "vc": anchor_ref, "bh": bh, "rh": rh, "bytes_hex": message.hex()},
        {"case": "minimal", "did": "did:key:z6MkExample", "from": "a@b.c", "t": 1,
         "vc": "chain:x", "bh": "sha256:00", "rh": "sha256:00",
         "bytes_hex": signing_input(
             "did:key:z6MkExample", "a@b.c", 1, "chain:x", "sha256:00", "sha256:00"
         ).hex()},
    ]

    payload_cases = [
        {"case": "main", "did": did, "email": "alice@example.com", "issuer_did": issuer,
         "hex": payload_hash_email_binding(did, "alice@example.com", issuer)},
        {"case": "different-issuer-changes-hash", "did": did, "email": "alice@example.com",
         "issuer_did": "did:web:other.example.com",
         "hex": payload_hash_email_binding(did, "alice@example.com", "did:web:other.example.com")},
    ]

    domain_cases = [
        {"case": "main", "domain": "example.com", "issuer_did": issuer,
         "hex": payload_hash_domain_control("example.com", issuer)},
        {"case": "uppercase-domain-normalized", "domain": "example.com", "issuer_did": issuer,
         "hex": payload_hash_domain_control("Example.COM".lower(), issuer)},
        {"case": "different-domain-changes-hash", "domain": "other.example.com", "issuer_did": issuer,
         "hex": payload_hash_domain_control("other.example.com", issuer)},
    ]
    assert domain_cases[0]["hex"] != domain_cases[2]["hex"]

    auth_cases = [
        {"case": "verified",
         "header": 'result=verified; integrity=pass; address=verified; did-id="%s"' % did},
        {"case": "failed-integrity",
         "header": "result=failed; integrity=fail; address=unknown; reason=body_hash_mismatch"},
        {"case": "failed-address",
         "header": "result=failed; integrity=pass; address=failed; reason=anchor_revoked"},
        {"case": "absent",
         "header": "result=failed; integrity=fail; address=unknown; reason=did_absent"},
    ]

    verdict_cases = [
        {"case": "no-did-object", "did": None, "own_verify": "did_absent", "policy": "enforce",
         "expect": {"action": "accept", "reason": "did_absent"}},
        {"case": "all-pass", "did": {"integrity": "pass"}, "own_verify": "ok", "policy": "enforce",
         "expect": {"action": "accept", "reason": ""}},
        {"case": "integrity-fail", "did": {"integrity": "fail"}, "own_verify": "body_hash_mismatch",
         "policy": "enforce",
         "expect": {"action": "reject", "reason": "body_hash_mismatch"}},
        {"case": "chain-unavailable",
         "did": {"integrity": "pass", "address": "failed", "reason": "chain_unavailable"},
         "own_verify": "ok", "policy": "enforce",
         "expect": {"action": "accept_flagged", "reason": "chain_unavailable"}},
        {"case": "anchor-revoked",
         "did": {"integrity": "pass", "address": "failed", "reason": "anchor_revoked"},
         "own_verify": "ok", "policy": "enforce",
         "expect": {"action": "reject", "reason": "anchor_revoked"}},
        {"case": "attachment-fetch-failed", "did": {"integrity": "pass"},
         "own_verify": "attachment_fetch_failed", "policy": "enforce",
         "expect": {"action": "accept_flagged", "reason": "attachment_fetch_failed"}},
        {"case": "missing-body-signed", "did": {"integrity": "pass"},
         "own_verify": "not_verifiable", "policy": "enforce",
         "expect": {"action": "accept_flagged", "reason": "not_verifiable"}},
        {"case": "record-only-never-rejects", "did": {"integrity": "fail"},
         "own_verify": "signature_invalid", "policy": "record",
         "expect": {"action": "accept", "reason": "signature_invalid"}},
    ]

    return {
        "about": (
            "DID-Signature / DID-Auth-Results 的字节向量（唯一事实源）。"
            "生成脚本 protocol/vectors/gen_did_vectors.py。"
            "任何字段布局变更必须同时改 protocol/DID-SIGNATURE-PROTOCOL.md。"
        ),
        "constants": {
            "header_name": HEADER_NAME,
            "results_header_name": RESULTS_HEADER_NAME,
            "system_mail_header": SYSTEM_MAIL_HEADER,
            "protocol_version": PROTOCOL_VERSION,
            "signing_tag": SIGNING_TAG,
            "content_tag": CONTENT_TAG,
            "email_binding_tag": EMAIL_BINDING_TAG,
            "domain_control_tag": DOMAIN_CONTROL_TAG,
            "body_hash_prefix": BODY_HASH_PREFIX,
            "anchor_hash_prefix": ANCHOR_HASH_PREFIX,
            "anchor_ref_prefix": ANCHOR_REF_PREFIX,
            "attachment_separator": ATTACHMENT_SEPARATOR,
            "errors": ERRORS,
        },
        "content_v1": content_cases,
        "rcpt_hash": rcpt_cases,
        "signing_input": signing_cases,
        "header": [
            {
                "case": "main",
                "fields": {
                    "v": PROTOCOL_VERSION,
                    "did": did,
                    "t": str(timestamp),
                    "s": b64url_nopad(signature),
                    "vc": anchor_ref,
                    "bh": bh,
                    "rh": rh,
                },
                "public_key_hex": public.hex(),
                "sig_hex": signature.hex(),
                "header": header,
                "unfolded_len": len(header),
            }
        ],
        "payload_hash": payload_cases,
        "domain_control": domain_cases,
        "auth_results": auth_cases,
        "verdict": verdict_cases,
        "payload": [
            {
                "case": "did-record",
                "has_did": True,
                "record_headers": {"did-signature": header},
                "expect_did_keys": [
                    "signature",
                    "body_signed",
                    "rcpt_to_raw",
                    "rcpt_cc_raw",
                    "attachments",
                    "gateway_time",
                    "results",
                ],
                "expect_absent_keys": ["sha256", "file_hash", "bh", "rh"],
            }
        ],
    }


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "protocol/vectors/did-signature.json"
    data = build()
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=False)
        handle.write("\n")
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
