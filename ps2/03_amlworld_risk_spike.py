"""
SetuGuard PS2 — Day 5-6 Risk Spike: AMLworld + NetworkX
==========================================================
Goal: NOT to produce real results. Just confirm the tooling works on
your machine before Fix #2 (graph features) is on the critical path
in Week 2-3. If this fails, you have 3 weeks of runway to find a
fallback instead of discovering the problem under deadline pressure.

Steps this script performs:
  1. Load a SUBSAMPLE of AMLworld HI-Small (don't try the full dataset
     yet -- that's a Week 2 problem)
  2. Build a NetworkX directed graph from the transactions
  3. Run Louvain community detection
  4. Run betweenness centrality (this is the slow one -- time it)
  5. Run PageRank
  6. Report: did everything run, and how long did it take on your subsample

Before running:
  1. Download AMLworld HI-Small from Kaggle:
     https://www.kaggle.com/datasets/ealtman2019/ibm-transactions-for-anti-money-laundering-aml
  2. pip install networkx python-louvain pandas

Usage:
    python 03_amlworld_risk_spike.py --csv path/to/HI-Small_Trans.csv --sample-frac 0.05
"""

import argparse
import time
import pandas as pd
import networkx as nx


def load_subsample(csv_path: str, sample_frac: float, seed: int = 42) -> pd.DataFrame:
    """
    AMLworld's HI-Small transaction file is large -- start small.
    Column names in the public release are typically:
      Timestamp, From Bank, Account, To Bank, Account.1,
      Amount Received, Receiving Currency, Amount Paid, Payment Currency,
      Payment Format, Is Laundering
    Adjust the column references below if your downloaded copy differs.
    """
    print(f"Loading {csv_path} ...")
    df = pd.read_csv(csv_path)
    print(f"Full shape: {df.shape}")

    df_sample = df.sample(frac=sample_frac, random_state=seed)
    print(f"Subsample shape ({sample_frac*100:.0f}%): {df_sample.shape}")
    return df_sample


def build_graph(df: pd.DataFrame, from_col: str = "Account", to_col: str = "Account.1") -> nx.DiGraph:
    t0 = time.time()
    G = nx.DiGraph()
    for _, row in df.iterrows():
        G.add_edge(row[from_col], row[to_col])
    elapsed = time.time() - t0
    print(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges "
          f"({elapsed:.2f}s)")
    return G


def run_community_detection(G: nx.DiGraph):
    """Louvain requires an undirected graph."""
    import community as community_louvain  # pip install python-louvain

    t0 = time.time()
    G_undirected = G.to_undirected()
    partition = community_louvain.best_partition(G_undirected)
    elapsed = time.time() - t0
    n_communities = len(set(partition.values()))
    print(f"Louvain: {n_communities} communities found ({elapsed:.2f}s)")
    return partition


def run_betweenness(G: nx.DiGraph, k: int = None):
    """
    Full betweenness centrality is O(V*E) -- can be very slow on large
    graphs. k=None computes exactly; pass a k value (sample size) to
    approximate on bigger graphs. On your subsample, try exact first
    and see how long it takes -- that number tells you whether you'll
    need approximation later.
    """
    t0 = time.time()
    scores = nx.betweenness_centrality(G, k=k, normalized=True)
    elapsed = time.time() - t0
    print(f"Betweenness centrality computed for {len(scores)} nodes ({elapsed:.2f}s)"
          + (f" [approximated with k={k}]" if k else " [exact]"))
    top5 = sorted(scores.items(), key=lambda x: -x[1])[:5]
    print(f"Top 5 by betweenness: {top5}")
    return scores


def run_pagerank(G: nx.DiGraph):
    t0 = time.time()
    scores = nx.pagerank(G)
    elapsed = time.time() - t0
    print(f"PageRank computed for {len(scores)} nodes ({elapsed:.2f}s)")
    top5 = sorted(scores.items(), key=lambda x: -x[1])[:5]
    print(f"Top 5 by PageRank: {top5}")
    return scores


def fan_in_out_ratio(G: nx.DiGraph):
    """Structural pass-through: fan-in vs fan-out per node."""
    ratios = {}
    for node in G.nodes():
        fan_in = G.in_degree(node)
        fan_out = G.out_degree(node)
        ratios[node] = fan_out / (fan_in + 1)  # +1 avoids div by zero
    return ratios


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to AMLworld HI-Small transactions CSV")
    parser.add_argument("--sample-frac", type=float, default=0.05,
                         help="Fraction of rows to sample for the spike (default 5%%)")
    parser.add_argument("--from-col", default="Account")
    parser.add_argument("--to-col", default="Account.1")
    parser.add_argument("--betweenness-approx-k", type=int, default=500,
                         help="Sample size k for fast approximated betweenness centrality (default 500). Pass -1 for exact computation.")
    args = parser.parse_args()

    print("=" * 60)
    print("RISK SPIKE: does AMLworld + NetworkX actually work?")
    print("Report the timings below back to the team, whatever they show.")
    print("=" * 60)

    df = load_subsample(args.csv, args.sample_frac)
    G = build_graph(df, args.from_col, args.to_col)

    try:
        run_community_detection(G)
    except Exception as e:
        print(f"FAILED at community detection: {e}")

    try:
        k_val = None if args.betweenness_approx_k == -1 else args.betweenness_approx_k
        run_betweenness(G, k=k_val)
    except Exception as e:
        print(f"FAILED at betweenness: {e}")

    try:
        run_pagerank(G)
    except Exception as e:
        print(f"FAILED at PageRank: {e}")

    ratios = fan_in_out_ratio(G)
    print(f"\nFan-in/out ratio computed for {len(ratios)} nodes -- sample: "
          f"{dict(list(ratios.items())[:5])}")

    print("\n--- Spike complete ---")
    print("If everything above ran without errors: you're clear to build")
    print("Fix #2 for real in Week 2. If betweenness was too slow: plan on")
    print("the approximate (k-sampled) version instead of exact.")
    print("If AMLworld itself failed to load or the graph was too sparse/dense")
    print("to be meaningful: flag this NOW so the team has a fallback plan.")
