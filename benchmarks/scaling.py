"""How does the system scale from 3 to 20 farms? Classical Flower vs our post-quantum system.

For each number of farms, three real training runs (Flower deployment mode, TLS 1.3, 15 rounds):

  classical    Flower as shipped: ECDSA P-384 login on every request, updates not signed
  pqc          ML-DSA-65 login on every request, ML-DSA-65 signed updates
  pqc-session  ML-DSA-65 login once per session, then HMAC session tags; signed updates (our system)

Measured per run: final test accuracy, mean round time, authenticated requests per farm per round
(SuperLink-side counter), and, for pqc-session, the auth bytes the farms actually sent. Login
traffic for classical and pqc is requests x header size from benchmarks/pqc_costs.py (section A);
the classical run itself is unmodified Flower, so it carries no counters.

Usage: python benchmarks/scaling.py [--farms 3,5,10,20] [--rounds 15] [--charts-only]
Each finished run is saved to results/scaling_runs.json, so an interrupted sweep resumes where it
stopped. Writes results/scaling_<date>.txt/.json and docs/paper/scaling_*.png.
Set PQC_CONTROL_PORT if port 8000 is taken.
"""

import argparse
import datetime
import json
import os
import re
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS_FILE = ROOT / "results/scaling_runs.json"
MODES = {
    "classical": "",
    "pqc": "sign-updates=true",
    "pqc-session": "sign-updates=true",
}
LABELS = {
    "classical": "Classical Flower (ECDSA login)",
    "pqc": "ML-DSA login on every request",
    "pqc-session": "ML-DSA session login (our system)",
}
COLORS = {"classical": "#c77c02", "pqc": "#2f6db5", "pqc-session": "#2e8b57"}


def header_bytes() -> dict[str, int]:
    """Login headers per request, from the latest PQC cost benchmark."""
    latest = sorted((ROOT / "results").glob("pqc_costs_*.json"))[-1]
    login = json.loads(latest.read_text())["login"]
    return {"ECDSA": login["ECDSA P-384"]["headers_on_wire_B"], "ML-DSA": login["ML-DSA-65"]["headers_on_wire_B"]}


def run(mode: str, farms: int, rounds: int) -> dict:
    count_file = ROOT / "logs/scaling_count.txt"
    bytes_file = ROOT / "logs/scaling_bytes.txt"
    count_file.unlink(missing_ok=True)
    bytes_file.unlink(missing_ok=True)
    env = dict(os.environ)
    if mode != "classical":
        env["PQC_LOGIN_COUNT_FILE"] = str(count_file)  # one line per ML-DSA verification (pqc_login.py)
    if mode == "pqc-session":
        env["PQC_LOGIN_BYTES_FILE"] = str(bytes_file)  # auth bytes per request (session_login.py)
    start = time.perf_counter()
    out = subprocess.run(
        [str(ROOT / "scripts/run_local.sh"), mode, str(farms), str(rounds), MODES[mode]],
        env=env, capture_output=True, text=True, cwd=ROOT,
    )
    if out.returncode != 0:
        raise RuntimeError(f"{mode} with {farms} farms failed:\n{out.stdout[-2000:]}\n{out.stderr[-2000:]}")
    evals = re.findall(r"\[round\s+(\d+)\] test_acc=([0-9.]+) .*round_time=([0-9.]+)s", out.stdout)
    acc_curve = [float(a) for _, a, _ in evals]
    round_times = [float(t) for r, _, t in evals if int(r) > 0]  # round 0 is the initial model
    rejected = len(re.findall(r"REJECTED", out.stdout))
    result = {
        "mode": mode, "farms": farms, "rounds": rounds,
        "final_acc": acc_curve[-1], "acc_curve": acc_curve,
        "mean_round_s": statistics.mean(round_times), "run_s": time.perf_counter() - start,
        "rejected_updates": rejected,
    }
    if count_file.exists():
        result["mldsa_verifications"] = len(count_file.read_text().splitlines())
    if bytes_file.exists():
        sizes = [int(x) for x in bytes_file.read_text().split()]
        result["requests"] = len(sizes)
        result["auth_KB_per_farm_round"] = sum(sizes) / 1024 / farms / rounds
    elif mode == "pqc":
        result["requests"] = result["mldsa_verifications"]  # every request is a full ML-DSA login
    return result


def login_kb(r: dict, headers: dict[str, int], requests_per_farm_round: float) -> float:
    if r["mode"] == "pqc-session":
        return r["auth_KB_per_farm_round"]
    size = headers["ML-DSA"] if r["mode"] == "pqc" else headers["ECDSA"]
    return requests_per_farm_round * size / 1024


def charts(table: list[dict], rounds: int) -> list[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                         "font.size": 11, "axes.spines.top": False, "axes.spines.right": False})
    out_dir = ROOT / "docs/paper"
    out_dir.mkdir(parents=True, exist_ok=True)
    farms = sorted({r["farms"] for r in table})
    by = {(r["mode"], r["farms"]): r for r in table}
    saved = []

    def line_chart(key, ylabel, name, percent=False, log=False):
        fig, ax = plt.subplots(figsize=(6, 3.6))
        for mode in MODES:
            ys = [by[mode, f][key] * (100 if percent else 1) for f in farms if (mode, f) in by]
            xs = [f for f in farms if (mode, f) in by]
            ax.plot(xs, ys, marker="o", color=COLORS[mode], label=LABELS[mode])
        ax.set_xlabel("Number of farms")
        ax.set_ylabel(ylabel)
        ax.set_xticks(farms)
        if log:
            ax.set_yscale("log")
        if percent:
            ax.set_ylim(0, 100)
        elif not log:
            ax.set_ylim(0, None)
        ax.grid(alpha=0.3)
        ax.legend(frameon=False, fontsize=9)
        fig.tight_layout()
        path = out_dir / f"scaling_{name}.png"
        fig.savefig(path, dpi=200)
        plt.close(fig)
        saved.append(path)

    line_chart("final_acc", f"Test accuracy after {rounds} rounds (%)", "accuracy", percent=True)
    line_chart("mean_round_s", "Mean round time (s)", "round_time")
    line_chart("login_KB", "Login traffic per farm per round (KB)", "login_traffic", log=True)

    # Accuracy per round at the largest farm count
    fig, ax = plt.subplots(figsize=(6, 3.6))
    for mode in MODES:
        if (mode, farms[-1]) in by:
            curve = by[mode, farms[-1]]["acc_curve"]
            ax.plot(range(len(curve)), [100 * a for a in curve], color=COLORS[mode], label=LABELS[mode])
    ax.set_xlabel("Round")
    ax.set_ylabel("Test accuracy (%)")
    ax.set_ylim(0, 100)
    ax.set_title(f"{farms[-1]} farms", fontsize=11)
    ax.grid(alpha=0.3)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    path = out_dir / "scaling_accuracy_per_round.png"
    fig.savefig(path, dpi=200)
    plt.close(fig)
    saved.append(path)
    return saved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--farms", default="3,5,10,20")
    parser.add_argument("--rounds", type=int, default=15)
    parser.add_argument("--charts-only", action="store_true")
    args = parser.parse_args()
    farm_counts = [int(f) for f in args.farms.split(",")]

    runs = json.loads(RUNS_FILE.read_text()) if RUNS_FILE.exists() else {}
    if not args.charts_only:
        for farms in farm_counts:
            for mode in MODES:
                key = f"{mode}/{farms}/{args.rounds}"
                if key in runs:
                    continue
                print(f"running {mode} with {farms} farms, {args.rounds} rounds ...", flush=True)
                runs[key] = run(mode, farms, args.rounds)
                RUNS_FILE.write_text(json.dumps(runs, indent=2) + "\n")
                r = runs[key]
                print(f"   accuracy {r['final_acc']:.3f}, mean round {r['mean_round_s']:.1f} s", flush=True)

    headers = header_bytes()
    table = []
    for farms in farm_counts:
        pqc = runs.get(f"pqc/{farms}/{args.rounds}")
        # Same Flower request pattern in every mode: requests per farm per round from the pqc run.
        per_farm_round = pqc["requests"] / farms / args.rounds if pqc else None
        for mode in MODES:
            r = runs.get(f"{mode}/{farms}/{args.rounds}")
            if not r or per_farm_round is None:
                continue
            table.append({**r, "requests_per_farm_round": per_farm_round,
                          "login_KB": login_kb(r, headers, per_farm_round)})

    date = datetime.date.today().isoformat()
    lines = [f"Scaling: classical Flower vs our PQC system, {args.rounds} rounds per run ({date})", "",
             f"{'farms':>5}  {'mode':<12}{'accuracy':>9}{'round time':>12}{'login KB/farm/round':>21}"
             f"{'ML-DSA verifs':>15}"]
    for r in table:
        lines.append(f"{r['farms']:>5}  {r['mode']:<12}{100 * r['final_acc']:>8.1f}%{r['mean_round_s']:>11.1f}s"
                     f"{r['login_KB']:>21.1f}{r.get('mldsa_verifications', 0):>15}")
    lines += ["", f"Requests per farm per round (pqc runs): "
              + ", ".join(f"{r['farms']} farms {r['requests_per_farm_round']:.1f}" for r in table if r["mode"] == "pqc"),
              f"Login header sizes per request: ECDSA {headers['ECDSA']} B, ML-DSA {headers['ML-DSA']} B"]
    text = "\n".join(lines) + "\n"
    print(text)
    out = ROOT / "results" / f"scaling_{date}"
    out.with_suffix(".txt").write_text(text)
    out.with_suffix(".json").write_text(json.dumps(table, indent=2) + "\n")
    for path in charts(table, args.rounds):
        print(f"saved {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
