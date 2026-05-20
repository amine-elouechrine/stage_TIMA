"""
benchmark_keys_F4.py — Benchmark multi-clés sur STM32F4, Config A (Tout SRAM).
Objectif : évaluer si la clé AES influence la résistance à l'attaque CPA.
Usage : source ~/.cwvenv/bin/activate && python3 benchmark_keys_F4.py
"""
import sys, os, subprocess, time
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import (
    compile_firmware, setup_scope, program_target,
    capture_traces, cpa_attack_full, find_min_traces,
    RESULTS_DIR, FW_PATH, plot_guessing_entropy
)
from collections import defaultdict
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# ─── Paramètres ────────────────────────────────────────────
N_RUNS   = 10
PLATFORM = 'CW308_STM32F4'
N_TRACES = 25
SEED     = 42     # Seed de base → chaque run aura son propre seed (SEED + run_idx)

# Clés à tester (doivent correspondre à KNOWN_KEY dans le firmware)
KEYS = [
    {
        'name': 'NIST',
        'label': 'Clé NIST (référence)',
        'key': bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                      0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]),
    },
    {
        'name': 'ZERO',
        'label': 'Clé nulle (HW=0)',
        'key': bytes([0x00]*16),
    },
    {
        'name': 'FF',
        'label': 'Clé maximale (HW=128)',
        'key': bytes([0xff]*16),
    },
    {
        'name': 'ALTERN',
        'label': 'Clé alternée (0xAA)',
        'key': bytes([0xaa]*16),
    },
    {
        'name': 'ONEBIT',
        'label': 'Clé 1 bit actif',
        'key': bytes([0x01]+[0x00]*15),
    },
    {
        'name': 'RANDOM',
        'label': 'Clé aléatoire réaliste',
        'key': bytes([0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]),
    },
]
# ──────────────────────────────────────────────────────────



os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── PHASE 1 : Compilation une seule fois (Config A = SRAM) ─
print(f"\n{'='*60}")
print(f"  PHASE 1 : COMPILATION CONFIG A (Tout SRAM)")
print(f"{'='*60}")
compile_firmware(PLATFORM, extra_opts='USE_CCM -DUSE_CCM_STACK')

# ─── PHASE 2 : Connexion scope ──────────────────────────────
print(f"\n{'='*60}")
print(f"  PHASE 2 : CONNEXION SCOPE")
print(f"{'='*60}")
scope, target = setup_scope(PLATFORM)

# Structures de résultats
results    = defaultdict(list)   # key_name -> [found_at, ...]
corrs      = defaultdict(list)   # key_name -> [max_corr, ...]
ranks_data = defaultdict(list)   # key_name -> [[r_hist], ...]
checkpoints_ref = None

try:
    for run_idx in range(1, N_RUNS + 1):
        run_seed = SEED + run_idx   # seed unique par run → plaintexts différents
        print(f"\n{'─'*55}")
        print(f"  RUN {run_idx}/{N_RUNS}  (seed={run_seed})")
        print(f"{'─'*55}")

        # Flash une seule fois par run (même firmware Config A pour toutes les clés)
        program_target(scope, target, PLATFORM)

        for key_cfg in KEYS:
            print(f"\n  [{key_cfg['name']}] {key_cfg['label']}")

            # Override KNOWN_KEY dans cpa_core pour ce test
            import cpa_core
            _orig_key = cpa_core.KNOWN_KEY
            cpa_core.KNOWN_KEY = key_cfg['key']
            
            
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES, seed=run_seed)
            print('---------',len(traces))
            # CPA : le modèle doit aussi utiliser la bonne clé
            checkpoints, _, corr_best, found_at, r_hist = find_min_traces(
                traces, 
                plaintexts, 
                known_key=key_cfg['key']
            )
            max_corr = corr_best[-1]


            cpa_core.KNOWN_KEY = _orig_key

            if checkpoints_ref is None:
                checkpoints_ref = checkpoints

            results[key_cfg['name']].append(found_at)
            corrs[key_cfg['name']].append(max_corr)
            ranks_data[key_cfg['name']].append(r_hist)

            found_str = str(found_at) if found_at else "N/A"
            ok = "✅" if found_at else "❌"
            print(f"  {key_cfg['name']}: {ok}  corr={max_corr:.4f}  min_traces={found_str}")

finally:
    scope.dis()
    target.dis()
    print("\n[INFO] Scope déconnecté.")

# ─── RÉSUMÉ ─────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  RÉSUMÉ FINAL — {N_RUNS} runs — Config A — {PLATFORM}")
print(f"{'='*60}")
print(f"{'Clé':<10} {'OK':>6} {'Corr moy':>12} {'Moy traces':>12} {'Min':>6} {'Max':>6}")
print(f"{'-'*55}")

for key_cfg in KEYS:
    k     = key_cfg['name']
    vals  = results[k]
    c     = corrs[k]
    valid = [v for v in vals if v is not None]
    ok    = f"{len(valid)}/{N_RUNS}"
    avg_c = sum(c) / len(c)
    avg_t = sum(valid) / len(valid) if valid else float('nan')
    mn    = min(valid) if valid else '-'
    mx    = max(valid) if valid else '-'
    print(f"  {k:<8} {ok:>6} {avg_c:>12.4f} {avg_t:>12.1f} {mn:>6} {mx:>6}")

    if checkpoints_ref is not None and len(ranks_data[k]) == N_RUNS:
        rmatrix    = np.array(ranks_data[k])
        mean_ranks = np.mean(rmatrix, axis=0)
        min_ranks  = np.min(rmatrix, axis=0)
        max_ranks  = np.max(rmatrix, axis=0)
        plot_guessing_entropy(
            checkpoints_ref, mean_ranks, min_ranks, max_ranks,
            title=f"Guessing Entropy — {key_cfg['label']} ({PLATFORM})",
            filename=f"guessing_entropy_{PLATFORM}_configA_key{k}.png"
        )

print(f"{'='*60}")

# ─── GRAPHE COMPARATIF ────────────────────────────────────
if checkpoints_ref is not None:
    fig, ax = plt.subplots(figsize=(12, 6))
    for key_cfg in KEYS:
        k = key_cfg['name']
        if len(ranks_data[k]) == N_RUNS:
            rmatrix    = np.array(ranks_data[k])
            mean_ranks = np.mean(rmatrix, axis=0)
            ax.plot(checkpoints_ref, mean_ranks, marker='o', markersize=2,
                    label=f"{key_cfg['name']} — {key_cfg['label']}")

    ax.set_title(f"Comparaison Guessing Entropy par Clé — Config A ({PLATFORM})", fontsize=13)
    ax.set_xlabel("Nombre de traces")
    ax.set_ylabel("Rang moyen de la clé (1 = trouvée)")
    ax.set_yscale('symlog')
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, f"comparison_keys_{PLATFORM}_configA.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"\n[PLOT] Graphe comparatif sauvegardé : {path}")
