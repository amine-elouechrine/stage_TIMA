"""
benchmark_F4.py — Benchmark optimisé pour STM32F4 :
  - Compile UNE SEULE FOIS par config
  - Flash automatiquement via st-flash (pas de prompt utilisateur)
  - Flash + capture N fois par config
Usage : source ~/.cwvenv/bin/activate && python3 benchmark_F4.py
"""
import sys, os, subprocess, time, shutil
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import (
    compile_firmware, setup_scope,
    capture_traces, cpa_attack, cpa_attack_full, dpa_attack_full, find_min_traces,
    KNOWN_KEY, RESULTS_DIR, FW_PATH, plot_guessing_entropy,
    plot_guessing_entropy_comparison
)
from collections import defaultdict

N_RUNS      = 5
PLATFORM    = 'CW308_STM32F4'
N_TRACES    = 150
SEED        = 42
ATTACK_MODE = 'DPA'   # ← 'CPA' ou 'DPA'

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


def flash_f4_auto(scope, extra_opts):
    """Flash le firmware F4 automatiquement via st-flash (sans prompt utilisateur)."""
    # Le bin file correspond au dernier firmware compilé avec extra_opts
    bin_file = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.bin")

    if not os.path.exists(bin_file):
        raise FileNotFoundError(f"Fichier BIN introuvable : {bin_file}")

    cmd = ["st-flash", "write", bin_file, "0x08000000"]
    print(f"  [FLASH F4] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  [FLASH F4] STDERR: {result.stderr.strip()}")
        raise RuntimeError("st-flash a échoué !")

    # Reset hardware pour démarrer le nouveau firmware
    scope.io.nrst = 'low'
    time.sleep(0.1)
    scope.io.nrst = 'high_z'
    time.sleep(2.5)   # Augmenté : F4 a besoin de temps pour démarrer après st-flash
    print(f"  [FLASH F4] OK — chip resetté.")


# ─── PHASE 1 : Compilation une seule fois ──────────────────
print(f"\n{'='*60}")
print(f"  PHASE 1 : COMPILATION (une seule fois par config)")
print(f"{'='*60}")
for cfg in CONFIGS:
    compile_firmware(PLATFORM, cfg['extra'])
    # Sauvegarde du binaire sous un nom unique pour cette config
    src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.bin")
    dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.bin")
    shutil.copy2(src, dst)
    print(f"[COMPILE] Binaire config{cfg['name']} sauvegardé : {dst}")

# ─── PHASE 2 : Connexion scope ─────────────────────────────
print(f"\n{'='*60}")
print(f"  PHASE 2 : CONNEXION SCOPE")
print(f"{'='*60}")
scope, target = setup_scope(PLATFORM)

results = defaultdict(list)
corrs   = defaultdict(list)
ranks_data = defaultdict(list)
checkpoints_ref = None
print('-------------------ATTACK MODE-----------------------',ATTACK_MODE)
try:
    for run_idx in range(1, N_RUNS + 1):
        run_seed = SEED + run_idx   # unique seed per run, shared across all configs
        print(f"\n{'─'*55}")
        print(f"  RUN {run_idx}/{N_RUNS}  (seed={run_seed})")
        print(f"{'─'*55}")

        for cfg in CONFIGS:
            print(f"\n  [{cfg['name']}] Flash + Capture...")

            # Restaure le bon binaire pour cette config avant le flash
            src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.bin")
            dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.bin")
            shutil.copy2(src, dst)

            # Flash automatique via st-flash (firmware déjà compilé en Phase 1)
            flash_f4_auto(scope, cfg['extra'])

            # Capture
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES, seed=run_seed)
            # Analyse sur les 16 octets (CPA ou DPA selon ATTACK_MODE)
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
    
    import numpy as np
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