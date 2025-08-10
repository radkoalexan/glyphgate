#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
glyphgate — ENS/name homograph & invisible-character detector (offline).

What it does
- analyze: Inspect one string (or many from file/stdin) for risky Unicode tricks.
- suggest:  Offer an ASCII-safe "defanged" suggestion when possible.
- score:    Compute a 0..100 risk score (mapped to LOW/MEDIUM/HIGH).
- svg-badge:Tiny badge with overall risk label.

Examples
  $ python glyphgate.py analyze "vitalík.eth" --pretty
  $ python glyphgate.py analyze names.txt --json report.json --svg badge.svg
  $ echo "xn--vitalik-9za.eth" | python glyphgate.py analyze - --pretty
"""

import json
import os
import sys
import unicodedata as ud
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Any, Optional

import click

# ------------------ Confusables / traps (curated minimal set) ------------------

# Invisible/formatting codepoints commonly abused
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x00A0: "NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
    0x2061: "FUNCTION APPLICATION",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}

# Handpicked cross-script confusables → ASCII
CONFUSABLES = {
    # Cyrillic
    "А": "A", "В": "B", "Е": "E", "І": "I", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "S", "Т": "T", "Х": "X",
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "s", "у": "y", "х": "x",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "μ": "m", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x", "υ": "y",
    # Latin stylized / fullwidth
    "Ｏ": "O", "Ｉ": "I", "Ａ": "A", "Ｓ": "S", "０": "0", "１": "1", "５": "5",
    # Common visually similar swaps
    "l": "l", "I": "I", "O": "O", "S": "S",
}

LOOKALIKE_PAIRS = [
    ("0", "O"), ("1", "l"), ("1", "I"), ("5", "S"), ("2", "Z"), ("8", "B")
]

# Basic script bins (very coarse, enough for ENS labels)
def script_of(ch: str) -> str:
    try:
        name = ud.name(ch)
    except ValueError:
        return "Unknown"
    if "CYRILLIC" in name: return "Cyrillic"
    if "GREEK" in name: return "Greek"
    if "LATIN" in name: return "Latin"
    if "ARABIC" in name: return "Arabic"
    if "HEBREW" in name: return "Hebrew"
    if "HANGUL" in name or "HIRAGANA" in name or "KATAKANA" in name: return "CJK"
    if "CJK" in name: return "CJK"
    return "Other"

def is_label_char(ch: str) -> bool:
    # Allow letters, numbers, hyphen, dot; ENS labels use LDH + unicode labels after normalization
    return ch.isalnum() or ch in "-._"

@dataclass
class Finding:
    level: str   # LOW / MEDIUM / HIGH
    kind: str
    message: str
    context: Dict[str, Any]

@dataclass
class Report:
    original: str
    normalized_nfkc: str
    ascii_suggestion: str
    scripts: Dict[str, int]
    confusable_hits: List[Tuple[str,str]]
    invisibles: List[Tuple[str,str]]
    lookalikes: List[Tuple[str,str]]
    findings: List[Finding]
    risk_score: int
    risk_label: str

# ------------------ Core analysis ------------------

def detect_invisibles(s: str) -> List[Tuple[str, str]]:
    hits = []
    for ch in s:
        cp = ord(ch)
        if cp in INVISIBLE:
            hits.append((ch, INVISIBLE[cp]))
    return hits

def detect_confusables(s: str) -> List[Tuple[str,str]]:
    hits = []
    for ch in s:
        if ch in CONFUSABLES and CONFUSABLES[ch] != ch:
            hits.append((ch, CONFUSABLES[ch]))
    return hits

def detect_lookalikes(s: str) -> List[Tuple[str,str]]:
    alnum = [ch for ch in s if ch.isalnum()]
    present = set(alnum)
    hits = []
    for a, b in LOOKALIKE_PAIRS:
        if a in present and b in present:
            hits.append((a, b))
    return hits

def script_mix(s: str) -> Dict[str,int]:
    counts: Dict[str,int] = {}
    for ch in s:
        if not is_label_char(ch): 
            continue
        sc = script_of(ch)
        counts[sc] = counts.get(sc, 0) + 1
    return counts

def ascii_suggest(s: str) -> str:
    # Replace known confusables & strip invisibles; keep ASCII letters/digits/hyphen/dot/underscore
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in INVISIBLE:
            continue
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        # Simple fallback: decompose NFKD and keep ASCII
        decomp = ud.normalize("NFKD", ch)
        ascii_only = "".join(c for c in decomp if ord(c) < 128 and is_label_char(c))
        if ascii_only:
            out.append(ascii_only)
        else:
            # keep as-is if safe ASCII, else mark with '?'
            out.append(ch if (ord(ch) < 128 and is_label_char(ch)) else "?")
    # Collapse consecutive '?'
    res = "".join(out)
    while "??" in res:
        res = res.replace("??", "?")
    return res

def score_findings(fs: List[Finding]) -> Tuple[int,str]:
    pts = 0
    for f in fs:
        pts += 35 if f.level == "HIGH" else 15 if f.level == "MEDIUM" else 5
    pts = min(100, pts)
    label = "HIGH" if pts >= 70 else "MEDIUM" if pts >= 30 else "LOW"
    return pts, label

def analyze_string(s: str) -> Report:
    s = s.strip()
    nfkc = ud.normalize("NFKC", s)

    invis = detect_invisibles(s)
    confs = detect_confusables(s)
    looks = detect_lookalikes(s)
    scripts = script_mix(s)

    fs: List[Finding] = []

    if invis:
        fs.append(Finding("HIGH", "invisible", "String contains invisible or formatting codepoints", {"invisibles": [name for _, name in invis]}))

    # Mixed script: Latin + (Cyrillic|Greek|CJK)
    risky_scripts = {"Cyrillic","Greek","CJK"}
    if "Latin" in scripts and any(sc in scripts for sc in risky_scripts):
        fs.append(Finding("HIGH", "mixed-script", "Mixed Latin with other scripts", {"scripts": scripts}))

    # Confusables
    if confs:
        fs.append(Finding("MEDIUM", "confusable", "Contains cross-script homoglyphs", {"hits": confs}))

    # Lookalikes (ASCII)
    if looks:
        fs.append(Finding("LOW", "lookalike", "Contains look-alike ASCII pairs (O/0, l/I/1, ...)", {"pairs": looks}))

    # Non-label characters
    bad = [ch for ch in s if not is_label_char(ch)]
    if bad:
        fs.append(Finding("LOW", "nonlabel", "Contains characters outside label set", {"chars": bad}))

    ascii_fix = ascii_suggest(s)
    if ascii_fix != s:
        fs.append(Finding("LOW", "suggest", "ASCII-safe suggestion available", {"suggestion": ascii_fix}))

    score, label = score_findings(fs)

    return Report(
        original=s,
        normalized_nfkc=nfkc,
        ascii_suggestion=ascii_fix,
        scripts=scripts,
        confusable_hits=confs,
        invisibles=invis,
        lookalikes=looks,
        findings=fs,
        risk_score=score,
        risk_label=label,
    )

# ------------------ CLI ------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """glyphgate — ENS/name homograph & invisible-character detector."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report(s).")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write SVG badge (first item).")
@click.option("--pretty", is_flag=True, help="Human-readable output.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    """
    Analyze a single string, a file (one per line), or '-' for stdin.
    """
    lines: List[str] = []
    if input_arg == "-":
        lines = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    elif os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    else:
        lines = [input_arg]

    reps: List[Report] = []
    for s in lines:
        try:
            reps.append(analyze_string(s))
        except Exception as e:
            reps.append(Report(
                original=s, normalized_nfkc=s, ascii_suggestion=s, scripts={},
                confusable_hits=[], invisibles=[], lookalikes=[],
                findings=[Finding("HIGH","error","analysis failed",{"error": str(e)})],
                risk_score=100, risk_label="HIGH"
            ))

    if pretty:
        for r in reps:
            click.echo(f"{r.original!r} → risk {r.risk_score}/100 ({r.risk_label})")
            if r.scripts:
                click.echo(f"  scripts: {r.scripts}")
            if r.invisibles:
                click.echo("  invisibles:")
                for ch, name in r.invisibles:
                    cp = f"U+{ord(ch):04X}"
                    click.echo(f"    - {cp} {name}")
            if r.confusable_hits:
                click.echo("  confusables:")
                for a, b in r.confusable_hits:
                    click.echo(f"    - {a} → {b}")
            if r.lookalikes:
                click.echo(f"  look-alikes: {r.lookalikes}")
            if r.ascii_suggestion and r.ascii_suggestion != r.original:
                click.echo(f"  suggestion: {r.ascii_suggestion}")
            # findings summary
            for f in r.findings:
                click.echo(f"   - {f.level}: {f.kind} — {f.message}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "original": r.original,
                "normalized_nfkc": r.normalized_nfkc,
                "ascii_suggestion": r.ascii_suggestion,
                "scripts": r.scripts,
                "confusable_hits": r.confusable_hits,
                "invisibles": r.invisibles,
                "lookalikes": r.lookalikes,
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "findings": [asdict(x) for x in r.findings],
            } for r in reps], f, indent=2)
        click.echo(f"Wrote JSON: {json_out}")

    if svg_out:
        r = reps[0]
        color = "#3fb950" if r.risk_score < 30 else "#d29922" if r.risk_score < 70 else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="760" height="48" role="img" aria-label="glyphgate">
  <rect width="760" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    glyphgate: risk {r.risk_score}/100 ({r.risk_label}) — {r.original[:28]}…
  </text>
  <circle cx="735" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        click.echo(json.dumps([asdict(x) for x in reps], indent=2))

if __name__ == "__main__":
    cli()
