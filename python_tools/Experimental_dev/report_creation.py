import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import pandas as pd
from pathlib import Path
import argparse

# Mapping from mutation_id to mutation name
MUTATION_NAMES = {
    1: "MutateVersionSpoofing",
    2: "MutatePaddingDCID",
    3: "MutatePaddingSCID",
    4: "Mutate0RTTInjection",
    5: "MutateHeaderFlagsFlip",
    6: "MutateLengthTamper",
    7: "Precursor0RTTThenInitial",
    8: "PrecursorHandshakeThenInitial",
    9: "PrecursorRetryThenInitial",
    10: "PrecursorVersionNegotiation"
}

# Global mutation totals to share between reports
mutation_totals = {}

def analyze_data(data, output_dir, label):
    original_packets = [entry for entry in data if entry.get('source') == 'original']
    mutated_packets = [entry for entry in data if entry.get('source') == 'mutated' or 'mutation_id' in entry]

    mutation_counter = Counter(entry['mutation_id'] for entry in mutated_packets if 'mutation_id' in entry)

    mutation_distribution = {
        mutation_id: {
            "name": MUTATION_NAMES.get(mutation_id, "Unknown"),
            "count": count
        }
        for mutation_id, count in mutation_counter.items()
    }

    summary = {
        "total_packets": len(data),
        "original_packets": len(original_packets),
        "mutated_packets": len(mutated_packets),
        "mutation_distribution": mutation_distribution
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / f"{label}_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    if not mutated_packets:
        print(f"⚠️ No mutated packets found in {label}. Skipping charts.")
        return

    mutation_df = pd.DataFrame([
        {
            "mutation_id": mid,
            "mutation_name": MUTATION_NAMES.get(mid, "Unknown"),
            "count": count
        }
        for mid, count in mutation_counter.items()
    ])

    # Bar chart
    bar_chart_path = output_dir / f"{label}_bar_chart.png"
    plt.figure(figsize=(12, 6))
    bars = plt.bar(mutation_df["mutation_name"], mutation_df["count"])
    plt.xticks(rotation=45, ha='right')
    plt.xlabel("Mutation Type")
    plt.ylabel("Count")
    plt.title(f"{label.capitalize()} - Count of Each Mutation Type")

    for bar, row in zip(bars, mutation_df.itertuples(index=False)):
        total_for_mutation = mutation_totals.get(row.mutation_id, row.count)
        percentage = 100 * row.count / total_for_mutation if total_for_mutation else 0
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + 1,
            f"{percentage:.1f}% of {total_for_mutation}",
            ha='center',
            va='bottom',
            fontsize=9
        )

    plt.tight_layout()
    plt.savefig(bar_chart_path)
    plt.close()

    # Pie chart
    pie_chart_path = output_dir / f"{label}_pie_chart.png"
    plt.figure(figsize=(8, 8))
    plt.pie(
        mutation_df["count"],
        labels=mutation_df["mutation_name"],
        autopct='%1.1f%%',
        startangle=140
    )
    plt.title(f"{label.capitalize()} - Mutation Type Distribution")
    plt.tight_layout()
    plt.savefig(pie_chart_path)
    plt.close()

    print(f"✅ {label.capitalize()} summary saved to: {summary_path}")
    print(f"📊 {label.capitalize()} bar chart saved to: {bar_chart_path}")
    print(f"🥤 {label.capitalize()} pie chart saved to: {pie_chart_path}")

def analyze_by_domain_and_type(data, output_dir, label):
    grouped = defaultdict(lambda: defaultdict(list))
    for entry in data:
        if 'mutation_id' not in entry or 'domain' not in entry:
            continue
        domain = entry['domain']
        rtype = entry.get('response_header', {}).get('packet_type', 'unknown')
        grouped[domain][rtype].append(entry)

    for domain, by_type in grouped.items():
        for rtype, entries in by_type.items():
            sublabel = f"{label}_{domain}_{rtype}"
            subdir = output_dir / label
            analyze_data(entries, subdir, sublabel)

def main(found_file, not_found_file, output_dir, responded_missing_file=None, responded_matched_file=None):
    output_path = Path(output_dir)
    found_data = json.load(open(found_file))
    not_found_data = json.load(open(not_found_file))

    global mutation_totals
    all_data = found_data + not_found_data

    if responded_missing_file:
        responded_missing_data = json.load(open(responded_missing_file))
        all_data += responded_missing_data
    else:
        responded_missing_data = []

    if responded_matched_file:
        responded_matched_data = json.load(open(responded_matched_file))
        all_data += responded_matched_data
    else:
        responded_matched_data = []

    for entry in all_data:
        if entry.get('mutation_id') is not None:
            mid = entry['mutation_id']
            mutation_totals[mid] = mutation_totals.get(mid, 0) + 1

    analyze_data(found_data, output_path, "found")
    analyze_data(not_found_data, output_path, "not_found")

    if responded_missing_data:
        analyze_data(responded_missing_data, output_path, "responded_missing")
        analyze_by_domain_and_type(responded_missing_data, output_path, "response_not_found")

    if responded_matched_data:
        analyze_data(responded_matched_data, output_path, "responded_matched")
        analyze_by_domain_and_type(responded_matched_data, output_path, "response_found")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate mutation reports.")
    parser.add_argument("found_file", help="Path to found.json")
    parser.add_argument("not_found_file", help="Path to not_found.json")
    parser.add_argument("output_dir", help="Directory to save the reports")
    parser.add_argument("--responded_missing", help="Optional path to responded_missing.json")
    parser.add_argument("--responded_matched", help="Optional path to responded_matched.json")
    args = parser.parse_args()

    main(
        args.found_file,
        args.not_found_file,
        args.output_dir,
        responded_missing_file=args.responded_missing,
        responded_matched_file=args.responded_matched
    )
