import json
import os
import sys

import matplotlib
matplotlib.use("Agg")  
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


COLOR_GOOD = "#2E7D32"   
COLOR_BAD = "#C62828"      
COLOR_NEUTRAL = "#1565C0"   
COLOR_ACCENT = "#6A1B9A" 
COLOR_GREY = "#757575"      

plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.6,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def load_results(path):
    with open(path, "r") as f:
        return json.load(f)


def find_input_path(argv):
    if len(argv) > 1:
        return argv[1]
    for candidate in ("metrics_results.json", "metrics_results_sandbox.json"):
        if os.path.exists(candidate):
            return candidate
    raise FileNotFoundError(
        "Could not find metrics_results.json or metrics_results_sandbox.json "
        "in the current directory. Pass the path explicitly: "
        "python generate_graphs.py /path/to/metrics_results.json"
    )


def savefig(fig, out_dir, name):
    path = os.path.join(out_dir, name)
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path}")


# per-attack rejection rate (Section A)
def chart_tamper_detection(results, out_dir):
    section = results.get("A_tamper_detection", {})
    per_attack = section.get("per_attack", {})
    if not per_attack:
        print("  [skip] no A_tamper_detection.per_attack data")
        return

    labels = list(per_attack.keys())
    rates = [100.0 * v["rejected"] / v["trials"] if v["trials"] else 0.0
             for v in per_attack.values()]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    y_pos = range(len(labels))
    colors = [COLOR_GOOD if r >= 99.9 else (COLOR_NEUTRAL if r >= 90 else COLOR_BAD)
              for r in rates]
    ax.barh(y_pos, rates, color=colors, edgecolor="white", height=0.65)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    ax.set_xlabel("Detection / rejection rate (%)")
    ax.set_title("Tamper & attack detection rate by attack type", fontweight="bold")
    ax.axvline(100, color=COLOR_GREY, linewidth=1, linestyle="--", alpha=0.6)

    for y, r, v in zip(y_pos, rates, per_attack.values()):
        ax.text(min(r + 1.5, 100.5), y, f"{r:.1f}%  ({v['rejected']}/{v['trials']})",
                 va="center", fontsize=8.5)

    savefig(fig, out_dir, "tamper_detection_per_attack.png")


# confusion matrix heatmap (Section A)
def chart_confusion_matrix(results, out_dir):
    conf = results.get("A_tamper_detection", {}).get("confusion", {})
    if not conf:
        print("  [skip] no A_tamper_detection.confusion data")
        return

    tp, fn = conf.get("TP", 0), conf.get("FN", 0)
    fp, tn = conf.get("FP", 0), conf.get("TN", 0)
    matrix = [[tp, fn], [fp, tn]]

    fig, ax = plt.subplots(figsize=(5.5, 5))
    im = ax.imshow(matrix, cmap="Greens", vmin=0)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted: Tampered", "Predicted: Legitimate"])
    ax.set_yticklabels(["Actual: Tampered", "Actual: Legitimate"])
    plt.setp(ax.get_xticklabels(), rotation=15, ha="right")

    max_val = max(max(row) for row in matrix) or 1
    for i in range(2):
        for j in range(2):
            val = matrix[i][j]
            txt_color = "white" if val > max_val * 0.6 else "black"
            ax.text(j, i, f"{val}", ha="center", va="center",
                     fontsize=16, fontweight="bold", color=txt_color)

    ax.set_title("Tamper-detection confusion matrix", fontweight="bold")
    fig.colorbar(im, ax=ax, shrink=0.8, label="Count")
    savefig(fig, out_dir, "confusion_matrix.png")


# Chart 3: avalanche effect, mean % bits flipped +/- std 
def chart_avalanche(results, out_dir):
    section = results.get("B_avalanche", {})
    if not section:
        print("  [skip] no B_avalanche data")
        return

    labels = list(section.keys())
    means = [v["mean"] for v in section.values()]
    stds = [v["std"] for v in section.values()]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = range(len(labels))
    colors = [COLOR_GOOD if 40 <= m <= 60 else COLOR_BAD for m in means]
    ax.bar(x, means, yerr=stds, capsize=4, color=colors, edgecolor="white")
    ax.axhline(50, color=COLOR_GREY, linestyle="--", linewidth=1, label="Ideal avalanche (50%)")
    ax.axhspan(40, 60, color=COLOR_GOOD, alpha=0.08, label="Acceptable band (40-60%)")
    ax.set_xticks(list(x))
    ax.set_xticklabels([l.replace(", ", ",\n") for l in labels], fontsize=7.5,
                        rotation=20, ha="right")
    ax.set_ylabel("Output bits flipped (%)")
    ax.set_ylim(0, max(means) + max(stds) + 15 if means else 100)
    ax.set_title("Avalanche effect: output change from a single 1-bit input change",
                 fontweight="bold")
    ax.legend(loc="upper right", fontsize=8)

    savefig(fig, out_dir, "avalanche_effect.png")


# Chart 4: randomness proportion-of-sequences pass rate
def chart_randomness(results, out_dir):
    section = results.get("C_randomness", {})
    if not section:
        print("  [skip] no C_randomness data")
        return

    labels = list(section.keys())
    proportions = [100.0 * v["proportion"] for v in section.values()]
    colors = [COLOR_GOOD if "whitened" in l else COLOR_BAD for l in labels]

    fig, ax = plt.subplots(figsize=(7.5, 5))
    bars = ax.bar(labels, proportions, color=colors, edgecolor="white", width=0.55)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Sequences passing NIST-style test (%)")
    ax.set_title("Randomness test pass rate: whitened output vs. raw chaos output",
                 fontweight="bold")
    plt.setp(ax.get_xticklabels(), rotation=15, ha="right")

    for bar, v in zip(bars, section.values()):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                 f"{v['passed']}/{v['sequences']}", ha="center", fontsize=9)

    savefig(fig, out_dir, "randomness_pass_rate.png")



def chart_ml_distinguisher(results, out_dir):
    section = results.get("D_distinguisher", {})
    if not section:
        print("  [skip] no D_distinguisher data")
        return

    labels, means, stds, colors = [], [], [], []
    for name, v in section.items():
        acc_mean, acc_std = v["scores"]["accuracy"]
        labels.append(name.replace(" / ", "\n"))
        means.append(100.0 * acc_mean)
        stds.append(100.0 * acc_std)
        is_control = "Positive control" in name or "Negative control" in name
        colors.append(COLOR_ACCENT if is_control else
                       (COLOR_GOOD if abs(acc_mean - 0.5) < 0.05 else COLOR_BAD))

    fig, ax = plt.subplots(figsize=(12, 7))
    x = range(len(labels))
    ax.bar(x, means, yerr=stds, capsize=4, color=colors, edgecolor="white", width=0.65)
    ax.axhline(50, color=COLOR_GREY, linestyle="--", linewidth=1,
               label="Chance level (50%) = indistinguishable from random")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=7.5, rotation=25, ha="right")
    ax.set_ylabel("Classifier accuracy (%)")
    ax.set_ylim(0, 112)
    ax.set_title("ML distinguisher accuracy: can a classifier tell our output from random?",
                 fontweight="bold")
    ax.legend(loc="upper center", fontsize=8, bbox_to_anchor=(0.5, 1.14), ncol=1)
    fig.subplots_adjust(bottom=0.32)

    savefig(fig, out_dir, "ml_distinguisher_accuracy.png")


# accuracy/precision/recall/F1 (Section E1)
def chart_per_level_metrics(results, out_dir):
    section = results.get("E_overall", {}).get("per_level", {})
    if not section:
        print("  [skip] no E_overall.per_level data")
        return

    levels = list(section.keys())
    metrics = ["accuracy", "precision", "recall", "f1"]
    colors = [COLOR_NEUTRAL, COLOR_ACCENT, COLOR_GOOD, "#EF6C00"]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    n_metrics = len(metrics)
    width = 0.8 / n_metrics
    x_base = range(len(levels))

    for i, (metric, color) in enumerate(zip(metrics, colors)):
        values = [100.0 * section[lvl][metric] for lvl in levels]
        offsets = [xb + (i - (n_metrics - 1) / 2) * width for xb in x_base]
        ax.bar(offsets, values, width=width, label=metric.capitalize(),
               color=color, edgecolor="white")

    ax.set_xticks(list(x_base))
    labels_with_model = [f"{lvl}\n({section[lvl].get('chaos_model', '')})" for lvl in levels]
    ax.set_xticklabels(labels_with_model)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Score (%)")
    ax.set_title("End-to-end pipeline accuracy by security level", fontweight="bold")
    ax.legend(loc="upper center", ncol=4, fontsize=8, bbox_to_anchor=(0.5, 1.12))

    savefig(fig, out_dir, "per_level_metrics.png")


def chart_entropy_comparison(results, out_dir):
    section = results.get("E_overall", {}).get("ciphertext_randomness", {})
    if not section or "plaintext_entropy" not in section:
        print("  [skip] no E_overall.ciphertext_randomness entropy data")
        return

    labels = ["Plaintext", "Ciphertext"]
    values = [section["plaintext_entropy"], section["ciphertext_entropy"]]
    colors = [COLOR_BAD, COLOR_GOOD]

    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    bars = ax.bar(labels, values, color=colors, edgecolor="white", width=0.5)
    ax.axhline(8.0, color=COLOR_GREY, linestyle="--", linewidth=1,
               label="Theoretical max (8.0 bits/byte)")
    ax.set_ylim(0, 8.6)
    ax.set_ylabel("Shannon entropy (bits / byte)")
    ax.set_title("Byte-level entropy: plaintext vs. ciphertext", fontweight="bold")
    ax.legend(loc="lower right", fontsize=8)

    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.08, f"{v:.3f}",
                 ha="center", fontsize=10, fontweight="bold")

    savefig(fig, out_dir, "entropy_comparison.png")


def main():
    in_path = find_input_path(sys.argv)
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "graphs"
    os.makedirs(out_dir, exist_ok=True)

    print(f"Loading results from: {in_path}")
    results = load_results(in_path)

    print(f"Writing charts to: {out_dir}/\n")
    chart_tamper_detection(results, out_dir)
    chart_confusion_matrix(results, out_dir)
    chart_avalanche(results, out_dir)
    chart_randomness(results, out_dir)
    chart_ml_distinguisher(results, out_dir)
    chart_per_level_metrics(results, out_dir)
    chart_entropy_comparison(results, out_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()