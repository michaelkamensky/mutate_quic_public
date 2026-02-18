#!/usr/bin/env python3
"""
mutation_outcomes_report.py

Create per-domain charts and summaries comparing a deduped "final" (weeded) log
against a deduped "original" log, grouped by mutation_id.

Deduplication rule:
  - Within each log, for each (domain, mutation_id), collapse duplicates that
    share the same canonicalized header-change signature derived from
    `packet_header_changes` (preferred) or a fallback diff computed from
    `packet_header_original` vs `packet_header_mutated`.

Outputs (in the chosen output directory):
  - <domain>__pie__<SENSOR>.png  (concentric donut: inner=Original, outer=Final)
  - <domain>__bar__<SENSOR>.png  (Final counts; labels show Final/Original %)
  - <domain>__summary__<SENSOR>.csv  (now includes mutation_name)
  - global_summary__<SENSOR>.csv      (now includes mutation_name)
  - <domain>__dedup_audit__<SENSOR>.json  (which rows were removed, and why)

Usage:
  python mutation_outcomes_report.py \
      --final path/to/final.jsonl \
      --original path/to/original.jsonl \
      --sensor Zeek \
      --out out_dir \
      [--img-format png]

Notes:
  * Accepts JSON array or JSONL inputs.
  * Domains are case-insensitive.
  * If Original has zero deduped count for a mutation_id, the bar label is "n/a".
  * The `--sensor` string (e.g., "Zeek" or "Suricata") is used in titles/files.
"""

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Mutation ID → Name mapping (from your snippet)
# ---------------------------------------------------------------------------

MUTATION_ID_TO_NAME: Dict[int, str] = {
    1: "MutateVersionSpoofing",
    2: "MutatePaddingDCID",
    3: "MutatePaddingSCID",
    4: "Mutate0RTTInjection",
    5: "MutateHeaderFlagsFlip",
    6: "MutateLengthTamper",
    7: "Precursor0RTTThenInitial",
    8: "PrecursorHandshakeThenInitial",
    9: "PrecursorRetryThenInitial",
    10: "PrecursorVersionNegotiationThenInitial",
}

def mutation_name(mid: int) -> str:
    return MUTATION_ID_TO_NAME.get(mid, "Unknown")


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def load_any_json(path: str) -> List[Dict[str, Any]]:
    """
    Load JSON array, single JSON object, or JSONL (one object per line).
    Returns a list of dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        head = f.read(2048)
        f.seek(0)
        stripped = head.lstrip()
        if not stripped:
            return []
        if stripped[0] == "[":
            return json.load(f)
        if stripped[0] == "{":
            # single object
            return [json.load(f)]
        # Assume JSONL
        records: List[Dict[str, Any]] = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        return records


def to_lower_or_none(x: Optional[str]) -> Optional[str]:
    return x.lower() if isinstance(x, str) else x


def canonicalize_change_triplet(ch: Dict[str, Any]) -> Tuple[str, str, str]:
    """Normalize a single {field, from, to} change to a stable tuple."""
    field = str(ch.get("field", ""))
    from_v = "" if ch.get("from", None) is None else str(ch.get("from"))
    to_v = "" if ch.get("to", None) is None else str(ch.get("to"))
    return (field, from_v, to_v)


FALLBACK_FIELDS = [
    "flags",
    "is_long",
    "version",
    "packet_type",
    "pn_length",
    "dcid",
    "scid",
    # We include remaining_payload only as a last resort; it’s large/noisy,
    # but helps differentiate genuinely different mutations when header_changes
    # is missing.
    "remaining_payload",
]


def fallback_header_diff(entry: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """
    Build a fallback diff triplet list from packet_header_original vs mutated.
    Only considers FALLBACK_FIELDS. Missing fields treated as None.
    """
    o = entry.get("packet_header_original", {}) or {}
    m = entry.get("packet_header_mutated", {}) or {}

    diffs: List[Tuple[str, str, str]] = []
    for field in FALLBACK_FIELDS:
        ov = o.get(field, None)
        mv = m.get(field, None)
        if ov != mv:
            diffs.append((field, "" if ov is None else str(ov), "" if mv is None else str(mv)))
    return diffs


def header_signature(entry: Dict[str, Any]) -> Tuple[Tuple[str, str, str], ...]:
    """
    Canonical header-change signature for deduplication.
    Prefers `packet_header_changes`. Falls back to computed diff if absent.
    Returned as a sorted tuple of (field, from, to) triples for set/dict keys.
    """
    phc = entry.get("packet_header_changes", None)
    triples: List[Tuple[str, str, str]] = []
    if isinstance(phc, list) and phc:
        for ch in phc:
            if isinstance(ch, dict) and "field" in ch:
                triples.append(canonicalize_change_triplet(ch))
    else:
        triples.extend(fallback_header_diff(entry))

    # Sort for canonical order
    triples.sort(key=lambda t: (t[0], t[1], t[2]))
    return tuple(triples)


def sanitize_domain_for_fn(domain: str) -> str:
    # Replace anything not alnum, dot, dash with underscore
    return re.sub(r"[^A-Za-z0-9.\-]+", "_", domain)


def dedupe_by_signature(
    rows: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Dedupe rows within this set by (domain_lower, mutation_id, header_signature).
    Returns (deduped_rows, audit_info).
    audit_info structure:
        {
          "removed": [
             {"index": int, "domain": str, "mutation_id": int, "signature": [triples...], "timestamp": "...", ...},
             ...
          ],
          "kept_keys": ["domain|mutation_id|sig_hash", ...]
        }
    """
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    audit_removed: List[Dict[str, Any]] = []

    for idx, row in enumerate(rows):
        domain = to_lower_or_none(row.get("domain", "unknown")) or "unknown"
        mut_id = row.get("mutation_id", None)
        try:
            mut_id_key = int(mut_id) if mut_id is not None else -1
        except Exception:
            mut_id_key = -1

        sig = header_signature(row)
        sig_hash = hash(sig)
        key = (domain, mut_id_key, sig_hash)
        if key in seen:
            audit_removed.append({
                "index": idx,
                "domain": domain,
                "mutation_id": mut_id_key,
                "signature": list(sig),
                "timestamp": row.get("timestamp", None),
                "mutation_name": row.get("mutation_name", mutation_name(mut_id_key)),
            })
            continue
        seen.add(key)
        deduped.append(row)

    audit = {
        "removed": audit_removed,
        "kept_keys": [f"{d}|{m}|{k}" for (d, m, k) in seen],
    }
    return deduped, audit


def count_by_domain_mutid(rows: List[Dict[str, Any]]) -> Dict[str, Dict[int, int]]:
    """
    Returns nested counts: domain -> mutation_id -> count
    """
    counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        domain = to_lower_or_none(r.get("domain", "unknown")) or "unknown"
        mut = r.get("mutation_id", -1)
        try:
            mut_id = int(mut)
        except Exception:
            mut_id = -1
        counts[domain][mut_id] += 1
    return counts


def union_mutation_ids(c1: Dict[int, int], c2: Dict[int, int]) -> List[int]:
    return sorted(set(c1.keys()) | set(c2.keys()))


def consistent_colors(mut_ids: List[int]) -> Dict[int, Tuple[float, float, float, float]]:
    """
    Deterministic color assignment using a Matplotlib colormap.
    """
    cmap = plt.get_cmap("tab20")  # 20-cycle; will repeat if >20
    colors = {}
    for i, mid in enumerate(sorted(mut_ids)):
        colors[mid] = cmap(i % 20)
    return colors


def donut_two_rings(
    domain: str,
    sensor: str,
    orig_counts: Dict[int, int],
    final_counts: Dict[int, int],
    out_path: str,
    img_format: str = "png",
):
    """
    Concentric donut: inner ring = Original, outer ring = Final, both split by mutation_id.
    Legend now shows "ID <n>: <mutation_name>".
    """
    mut_ids = sorted(set(orig_counts.keys()) | set(final_counts.keys()))
    if not mut_ids:
        return

    colors = consistent_colors(mut_ids)

    inner_sizes = [orig_counts.get(mid, 0) for mid in mut_ids]
    outer_sizes = [final_counts.get(mid, 0) for mid in mut_ids]

    if sum(inner_sizes) == 0 and sum(outer_sizes) == 0:
        return

    fig, ax = plt.subplots(figsize=(9, 9))

    wedges1, _ = ax.pie(
        inner_sizes,
        radius=1.0,
        labels=None,
        startangle=90,
        wedgeprops=dict(width=0.3, edgecolor="white"),
        colors=[colors[mid] for mid in mut_ids],
    )

    wedges2, _ = ax.pie(
        outer_sizes,
        radius=1.32,
        labels=None,
        startangle=90,
        wedgeprops=dict(width=0.3, edgecolor="white"),
        colors=[colors[mid] for mid in mut_ids],
    )

    ax.text(0, 0.02, "Original", ha="center", va="center", fontsize=11, fontweight="bold")
    ax.text(0, -0.16, "Final", ha="center", va="center", fontsize=11, fontweight="bold")

    legend_labels = [f"ID {mid}: {mutation_name(mid)}" for mid in mut_ids]
    ax.legend(
        handles=wedges2,
        labels=legend_labels,
        title="mutation_id → name",
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
    )

    total_o = sum(inner_sizes)
    total_f = sum(outer_sizes)
    ax.set_title(
        f"{domain} — Mutation distribution (Original vs Final)\nSensor: {sensor} | Original={total_o} Final={total_f}",
        fontsize=12,
    )

    plt.tight_layout()
    fn = f"{sanitize_domain_for_fn(domain)}__pie__{sensor}.{img_format}"
    plt.savefig(os.path.join(out_path, fn), dpi=160)
    plt.close(fig)


def bar_final_with_pct(
    domain: str,
    sensor: str,
    orig_counts: Dict[int, int],
    final_counts: Dict[int, int],
    out_path: str,
    img_format: str = "png",
):
    """
    Bar chart for Final counts with percentage labels (Final / Original) per mutation_id.
    X-axis ticks include "ID n: mutation_name" (rotated for readability).
    """
    mut_ids = sorted(set(orig_counts.keys()) | set(final_counts.keys()))
    if not mut_ids:
        return

    colors = consistent_colors(mut_ids)
    y = [final_counts.get(mid, 0) for mid in mut_ids]
    fig, ax = plt.subplots(figsize=(12, 7))

    x_labels = [f"ID {mid}: {mutation_name(mid)}" for mid in mut_ids]
    bars = ax.bar(range(len(mut_ids)), y, color=[colors[mid] for mid in mut_ids])

    # Percentage labels above bars
    max_y = max(y) if y else 0
    for i, (bar, mid) in enumerate(zip(bars, mut_ids)):
        f = final_counts.get(mid, 0)
        o = orig_counts.get(mid, 0)
        label = f"{(100.0 * f / o):.1f}%" if o > 0 else "n/a"
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + max(0.5, 0.03 * (max_y if max_y > 0 else 1)),
            label,
            ha="center",
            va="bottom",
            fontsize=10,
        )

    ax.set_xticks(range(len(mut_ids)))
    ax.set_xticklabels(x_labels, rotation=30, ha="right")
    ax.set_xlabel("Mutation (ID → name)")
    ax.set_ylabel("Final (deduped) count")
    ax.set_title(f"{domain} — Final counts with % of Original (deduped)\nSensor: {sensor}")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()

    fn = f"{sanitize_domain_for_fn(domain)}__bar__{sensor}.{img_format}"
    plt.savefig(os.path.join(out_path, fn), dpi=160)
    plt.close(fig)


def write_domain_csv(
    domain: str,
    sensor: str,
    orig_counts: Dict[int, int],
    final_counts: Dict[int, int],
    out_dir: str,
):
    rows = []
    mut_ids = sorted(set(orig_counts.keys()) | set(final_counts.keys()))
    for mid in mut_ids:
        o = orig_counts.get(mid, 0)
        f = final_counts.get(mid, 0)
        pct = (f / o) if o > 0 else None
        rows.append({
            "domain": domain,
            "mutation_id": mid,
            "mutation_name": mutation_name(mid),
            "original_dedup": o,
            "final_dedup": f,
            "pct_final_of_original": (f"{pct:.4f}" if pct is not None else "n/a"),
        })

    fn = os.path.join(out_dir, f"{sanitize_domain_for_fn(domain)}__summary__{sensor}.csv")
    with open(fn, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["domain", "mutation_id", "mutation_name", "original_dedup", "final_dedup", "pct_final_of_original"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_global_csv(
    sensor: str,
    all_domains: List[str],
    orig_counts_by_domain: Dict[str, Dict[int, int]],
    final_counts_by_domain: Dict[str, Dict[int, int]],
    out_dir: str,
):
    rows = []
    for domain in sorted(all_domains):
        oc = orig_counts_by_domain.get(domain, {})
        fc = final_counts_by_domain.get(domain, {})
        mut_ids = sorted(set(oc.keys()) | set(fc.keys()))
        for mid in mut_ids:
            o = oc.get(mid, 0)
            f = fc.get(mid, 0)
            pct = (f / o) if o > 0 else None
            rows.append({
                "domain": domain,
                "mutation_id": mid,
                "mutation_name": mutation_name(mid),
                "original_dedup": o,
                "final_dedup": f,
                "pct_final_of_original": (f"{pct:.4f}" if pct is not None else "n/a"),
            })

    fn = os.path.join(out_dir, f"global_summary__{sensor}.csv")
    with open(fn, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["domain", "mutation_id", "mutation_name", "original_dedup", "final_dedup", "pct_final_of_original"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_audit_json(domain: str, sensor: str, audit: Dict[str, Any], out_dir: str, which: str):
    """
    which = "final" or "original"
    """
    fn = os.path.join(out_dir, f"{sanitize_domain_for_fn(domain)}__dedup_audit__{which}__{sensor}.json")
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Compare final vs original logs (deduped) and produce per-domain charts.")
    ap.add_argument("--final", required=True, help="Path to FINAL (weeded) log: JSON array/object or JSONL")
    ap.add_argument("--original", required=True, help="Path to ORIGINAL log: JSON array/object or JSONL")
    ap.add_argument("--sensor", required=True, choices=["Zeek", "Suricata"], help="Label for charts/files")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--img-format", default="png", choices=["png", "svg"], help="Image format")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # Load logs
    final_rows_raw = load_any_json(args.final)
    orig_rows_raw = load_any_json(args.original)

    # Normalize domains to lowercase up front
    for r in final_rows_raw:
        if "domain" in r and isinstance(r["domain"], str):
            r["domain"] = r["domain"].lower()
    for r in orig_rows_raw:
        if "domain" in r and isinstance(r["domain"], str):
            r["domain"] = r["domain"].lower()

    # Dedupe (per log, across (domain, mutation_id, header_signature))
    final_dedup, final_audit = dedupe_by_signature(final_rows_raw)
    orig_dedup, orig_audit = dedupe_by_signature(orig_rows_raw)

    # Helper: group by domain
    def by_domain(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        d: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in rows:
            d[to_lower_or_none(r.get("domain", "unknown")) or "unknown"].append(r)
        return d

    final_by_domain = by_domain(final_dedup)
    orig_by_domain = by_domain(orig_dedup)

    # Count per domain × mutation_id
    def counts_for_domain(rows: List[Dict[str, Any]]) -> Dict[str, Dict[int, int]]:
        c = defaultdict(lambda: defaultdict(int))
        for r in rows:
            domain = to_lower_or_none(r.get("domain", "unknown")) or "unknown"
            try:
                mid = int(r.get("mutation_id", -1))
            except Exception:
                mid = -1
            c[domain][mid] += 1
        return c

    final_counts_by_domain = counts_for_domain(final_dedup)
    orig_counts_by_domain = counts_for_domain(orig_dedup)

    all_domains = sorted(set(orig_by_domain.keys()) | set(final_by_domain.keys()))
    if not all_domains:
        print("No domains found after loading/deduplication. Nothing to plot.")
        return

    # Per-domain outputs
    for domain in all_domains:
        oc = orig_counts_by_domain.get(domain, {})
        fc = final_counts_by_domain.get(domain, {})

        # Charts
        donut_two_rings(
            domain=domain,
            sensor=args.sensor,
            orig_counts=oc,
            final_counts=fc,
            out_path=args.out,
            img_format=args.img_format,
        )
        bar_final_with_pct(
            domain=domain,
            sensor=args.sensor,
            orig_counts=oc,
            final_counts=fc,
            out_path=args.out,
            img_format=args.img_format,
        )

        # Per-domain CSV
        write_domain_csv(domain, args.sensor, oc, fc, args.out)

        # Per-domain dedup audit JSON (filter audits for this domain)
        def filter_audit(audit_obj: Dict[str, Any], domain_key: str) -> Dict[str, Any]:
            removed = [
                x for x in audit_obj.get("removed", [])
                if (x.get("domain", None) == domain_key)
            ]
            return {"removed": removed}

        write_audit_json(domain, args.sensor, filter_audit(final_audit, domain), args.out, which="final")
        write_audit_json(domain, args.sensor, filter_audit(orig_audit, domain), args.out, which="original")

    # Global CSV
    # Note: include mutation_name
    rows = []
    for domain in all_domains:
        oc = orig_counts_by_domain.get(domain, {})
        fc = final_counts_by_domain.get(domain, {})
        for mid in sorted(set(oc.keys()) | set(fc.keys())):
            o = oc.get(mid, 0)
            f = fc.get(mid, 0)
            pct = (f / o) if o > 0 else None
            rows.append({
                "domain": domain,
                "mutation_id": mid,
                "mutation_name": mutation_name(mid),
                "original_dedup": o,
                "final_dedup": f,
                "pct_final_of_original": (f"{pct:.4f}" if pct is not None else "n/a"),
            })

    fn = os.path.join(args.out, f"global_summary__{args.sensor}.csv")
    with open(fn, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["domain", "mutation_id", "mutation_name", "original_dedup", "final_dedup", "pct_final_of_original"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Done. Wrote charts, CSVs, and audits into: {args.out}")


if __name__ == "__main__":
    main()
