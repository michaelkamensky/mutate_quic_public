import os
import sys
import json
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
from datetime import datetime

MUTATION_NAME_MAP = {
    "1": "Version Spoofing",
    "2": "Padding DCID",
    "3": "Padding SCID",
    "4": "0-RTT Injection",
    "5": "Header Flags Flip",
    "6": "Length Tamper",
    "7": "Precursor 0-RTT → Initial",
    "8": "Precursor Handshake → Initial",
    "9": "Precursor Retry → Initial",
    "10": "Precursor Version Negotiation → Initial"
}


def parse_log(filepath):
    domain_counter = Counter()
    mutation_counter = Counter()
    original_vs_mutation = defaultdict(lambda: Counter())

    with open(filepath, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                domain = entry.get("domain", "unknown")
                mutation_id = str(entry.get("mutation_id", "unknown"))
                mutation = MUTATION_NAME_MAP.get(mutation_id, f"Unknown ({mutation_id})")
                original = entry.get("original", "none")
                domain_counter[domain] += 1
                mutation_counter[mutation] += 1
                original_vs_mutation[domain][mutation] += 1
            except json.JSONDecodeError:
                continue

    total = sum(mutation_counter.values())
    mutation_percent = {
        k: (v / total) * 100 for k, v in mutation_counter.items()
    } if total > 0 else {}
    return {
        "domain_counter": domain_counter,
        "mutation_counter": mutation_counter,
        "original_vs_mutation": original_vs_mutation,
        "mutation_percent": mutation_percent,
        "total_mutations": total
    }

def save_report(report, output_path):
    with open(output_path, 'w') as f:
        json.dump({
            "domain_counts": dict(report["domain_counter"]),
            "mutation_counts": dict(report["mutation_counter"]),
            "mutation_percentages": report["mutation_percent"],
            "total_mutations": report["total_mutations"]
        }, f, indent=2)

def generate_graphs(report, label, output_dir):
    # Pie chart
    pie_path = os.path.join(output_dir, f"{label}_pie.png")
    if report["mutation_percent"]:
        plt.figure()
        labels, sizes = zip(*report["mutation_percent"].items())
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(f"{label.capitalize()} - Mutation Distribution")
        plt.savefig(pie_path)
        plt.close()

    # Bar chart
    bar_path = os.path.join(output_dir, f"{label}_bar.png")
    if report["mutation_counter"]:
        plt.figure()
        mutations = list(report["mutation_counter"].keys())
        counts = list(report["mutation_counter"].values())
        plt.bar(mutations, counts)
        plt.title(f"{label.capitalize()} - Mutation Counts")
        plt.xlabel("Mutation ID")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(bar_path)
        plt.close()

def main():
    if len(sys.argv) != 4:
        print("Usage: python generate_quic_report.py <matched_file> <unmatched_file> <output_dir>")
        sys.exit(1)

    matched_file = sys.argv[1]
    unmatched_file = sys.argv[2]
    output_dir = sys.argv[3]

    os.makedirs(output_dir, exist_ok=True)

    print("📊 Processing matched packets...")
    matched_report = parse_log(matched_file)
    save_report(matched_report, os.path.join(output_dir, "report_1.json"))
    generate_graphs(matched_report, "matched", output_dir)

    print("📊 Processing unmatched packets...")
    unmatched_report = parse_log(unmatched_file)
    save_report(unmatched_report, os.path.join(output_dir, "report_2.json"))
    generate_graphs(unmatched_report, "unmatched", output_dir)

    print("\n✅ Reports and graphs generated in:", output_dir)

if __name__ == "__main__":
    main()
