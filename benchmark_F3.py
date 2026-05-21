"""
benchmark.py — Benchmark optimisé : compile UNE SEULE FOIS, puis flash+capture N fois.
Usage : source ~/.cwvenv/bin/activate && python3 benchmark.py
"""
import sys, os, shutil
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import (
    compile_firmware, setup_scope, program_target,
    capture_traces, cpa_attack, cpa_attack_full, dpa_attack_full, find_min_traces,
    KNOWN_KEY, RESULTS_DIR, FW_PATH, plot_guessing_entropy,
    plot_guessing_entropy_comparison
)
import numpy as np

N_RUNS      = 5
PLATFORM    = 'CW308_STM32F3'
N_TRACES    = 150
SEED        = 42   # seed fixe → mêmes plaintexts à chaque run
ATTACK_MODE = 'CPA'   # ← 'CPA' ou 'DPA'

# Sélection automatique de la fonction d'attaque
_attack_fn = cpa_attack_full if ATTACK_MODE == 'CPA' else dpa_attack_full
print(f"[MODE] Attaque sélectionnée : {ATTACK_MODE}")

CONFIGS = [
    {'name': 'A', 'label': 'Config A — Tout SRAM',           'extra': ''},
    {'name': 'B', 'label': 'Config B — Clé CCM, S-Box SRAM', 'extra': 'USE_CCM_KEY'},
    {'name': 'C', 'label': 'Config C — Tout CCM',            'extra': 'USE_CCM'},
    {'name': 'D', 'label': 'Config D — Clé SRAM, S-Box CCM', 'extra': 'USE_CCM_SBOX'},
    {'name': 'E', 'label': 'Config E — Pile (Stack) en CCM', 'extra': 'USE_CCM_STACK'},
    {'name': 'F', 'label': 'Config F — Clé CCM, Pile CCM, S-Box SRAM', 'extra': 'USE_CCM_KEY -DUSE_CCM_STACK'},
    {'name': 'G', 'label': 'Config G — S-Box CCM, Pile CCM, Clé SRAM', 'extra': 'USE_CCM_SBOX -DUSE_CCM_STACK'},
    {'name': 'H', 'label': 'Config H — Tout CCM (Clé, S-Box, Pile)',  'extra': 'USE_CCM -DUSE_CCM_STACK'},
]

os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── PHASE 1 : Compilation une seule fois ──────────────────
print(f"\n{'='*60}")
print(f"  PHASE 1 : COMPILATION (une seule fois par config)")
print(f"{'='*60}")
for cfg in CONFIGS:
    compile_firmware(PLATFORM, cfg['extra'])
    # Sauvegarde du binaire sous un nom unique pour cette config sinon on va ecraser la compilation precedente
    src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.hex")
    dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.hex")
    shutil.copy2(src, dst)
    print(f"[COMPILE] Binaire config{cfg['name']} sauvegardé : {dst}")

# ─── PHASE 2 : Connexion scope ─────────────────────────────
print(f"\n{'='*60}")
print(f"  PHASE 2 : CONNEXION SCOPE")
print(f"{'='*60}")
scope, target = setup_scope(PLATFORM)

# Structures de résultats : config -> liste de min_traces
from collections import defaultdict
results = defaultdict(list)   # cfg name -> [min_traces, ...]
corrs   = defaultdict(list)   # cfg name -> [max_corr, ...]
ranks_data = defaultdict(list)# cfg name -> [[ranks1], [ranks2], ...]
checkpoints_ref = None
print('------------ATTACK-------------------',ATTACK_MODE)
try:
    for run_idx in range(1, N_RUNS + 1):
        run_seed = SEED + run_idx   # unique seed per run, shared across all configs
        print(f"\n{'─'*55}")
        print(f"  RUN {run_idx}/{N_RUNS}  (seed={run_seed})")
        print(f"{'─'*55}")

        for cfg in CONFIGS:
            print(f"\n  [{cfg['name']}] Flash + Capture...")

            # Restaure le bon binaire pour cette config avant le flash
            src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.hex")
            dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.hex")
            shutil.copy2(src, dst)
            program_target(scope, target, PLATFORM)

            # Capture
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES, seed=run_seed)


            checkpoints, _, corr_best, found_at, r_hist = find_min_traces(
                traces, plaintexts, attack_fn=_attack_fn)
            max_corr = corr_best[-1]
            
            if checkpoints_ref is None:
                checkpoints_ref = checkpoints

            results[cfg['name']].append(found_at)
            corrs[cfg['name']].append(max_corr)
            ranks_data[cfg['name']].append(r_hist)

            found_str = str(found_at) if found_at else "N/A"
            ok = "✅" if found_at else "❌"
            print(f"  Config {cfg['name']}: {ok}  corr={max_corr:.4f}  min_traces={found_str}")

finally:
    scope.dis()
    target.dis()
    print("\n[INFO] Scope déconnecté.")

# ─── RÉSUMÉ ────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  RÉSUMÉ FINAL — Moyenne sur {N_RUNS} runs ({PLATFORM})")
print(f"{'='*60}")
print(f"{'Config':<10} {'OK':>6} {'Corr moy':>12} {'Moy traces':>12} {'Min':>6} {'Max':>6}")
print(f"{'-'*55}")

for cfg in CONFIGS:
    k     = cfg['name']
    vals  = results[k]
    c     = corrs[k]
    valid = [v for v in vals if v is not None]
    ok    = f"{len(valid)}/{N_RUNS}"
    avg_c = sum(c) / len(c)
    avg_t = sum(valid) / len(valid) if valid else float('nan')
    mn    = min(valid) if valid else '-'
    mx    = max(valid) if valid else '-'
    print(f"  Config {k:<5} {ok:>6} {avg_c:>12.4f} {avg_t:>12.1f} {mn:>6} {mx:>6}")

    if checkpoints_ref is not None and len(ranks_data[k]) == N_RUNS:
        rmatrix = np.array(ranks_data[k])
        mean_ranks = np.mean(rmatrix, axis=0)
        min_ranks = np.min(rmatrix, axis=0)
        max_ranks = np.max(rmatrix, axis=0)
        plot_guessing_entropy(checkpoints_ref, mean_ranks, min_ranks, max_ranks,
                              title=f"Entropie de Devinette ({ATTACK_MODE}) — {cfg['label']} ({PLATFORM})",
                              filename=f"guessing_entropy_{ATTACK_MODE.lower()}_{PLATFORM}_config{k}.png")

# ─── Graphe comparatif global de l'entropie de devinette ───
if checkpoints_ref is not None:
    plot_guessing_entropy_comparison(checkpoints_ref, ranks_data, CONFIGS, PLATFORM, attack_mode=ATTACK_MODE)

print(f"{'='*60}")
