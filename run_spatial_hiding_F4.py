"""
run_spatial_hiding_F4.py — Contre-mesure Spatial Hiding sur STM32F4
Fusionne et mélange les traces de 8 configurations différentes pour simuler
un attaquant face au Spatial Hiding. Lance CPA ET DPA sur le même dataset.
"""
import sys, os, shutil
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import *

# ─── Paramètres ───────────────────────────────────────────
PLATFORM            = 'CW308_STM32F4'
N_TRACES_PER_CONFIG = 10000       # traces par config (80 000 au total)
SEED                = 42
ATTACK_MODES        = ['CPA', 'DPA']  # Les deux attaques sur le même dataset
NB_ITERATIONS       = 3               # Nombre de runs pour moyenner les résultats
FORCE_RECOMPILE     = True            # Mettre False après la 1ère compilation correcte
CONFIG_NAME         = 'SPATIAL_HIDING_MERGED'
# ──────────────────────────────────────────────────────────

_attack_fns = {
    'CPA': cpa_attack_full,
    'DPA': dpa_attack_full,
}

# Matrice des configurations Spatial Hiding :
#  bit 0 (RoundKey) : USE_CCM_KEY force RoundKey en CCM (override LFSR bit 0)
#  bit 1 (SBOX)     : USE_CCM_SBOX force SBOX en CCM    (override LFSR bit 1)
#  bit 2 (State)    : USE_CCM / USE_CCM_STACK force state en CCM
#  USE_CCM seul     : force RoundKey + SBOX + state en CCM
#  USE_CCM_STACK    : state en CCM + déplace _estack en CCM via linker
CONFIGS = [
    {'name': 'A', 'extra': 'USE_SPATIAL_HIDING'},
    {'name': 'B', 'extra': 'USE_SPATIAL_HIDING USE_CCM_KEY'},
    {'name': 'C', 'extra': 'USE_SPATIAL_HIDING USE_CCM'},
    {'name': 'D', 'extra': 'USE_SPATIAL_HIDING USE_CCM_SBOX'},
    {'name': 'E', 'extra': 'USE_SPATIAL_HIDING USE_CCM_STACK'},
    {'name': 'F', 'extra': 'USE_SPATIAL_HIDING USE_CCM_KEY USE_CCM_STACK'},
    {'name': 'G', 'extra': 'USE_SPATIAL_HIDING USE_CCM_SBOX USE_CCM_STACK'},
    {'name': 'H', 'extra': 'USE_SPATIAL_HIDING USE_CCM USE_CCM_STACK'},
]

if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ext = "bin"  # F4 → BIN (flashé via st-flash)

    # ─── PHASE 1 : Compilation des 8 firmwares ─────────────
    print(f"\n{'='*60}\n  PHASE 1 : COMPILATION DES 8 CONFIGURATIONS\n{'='*60}")
    for cfg in CONFIGS:
        dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.{ext}")
        if FORCE_RECOMPILE or not os.path.exists(dst):
            print(f"[COMPILE] Config {cfg['name']} : {cfg['extra']}")
            compile_firmware(PLATFORM, cfg['extra'])
            src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.{ext}")
            shutil.copy2(src, dst)
        else:
            print(f"[CACHE]   Config {cfg['name']} déjà compilée.")

    # ─── Structures de résultats par mode d'attaque ────────
    # results[mode] = {'ranks_history': [], 'corr_correct': [], 'corr_best': [], 'found_at': []}
    results = {
        mode: {'ranks_history': [], 'corr_correct': [], 'corr_best': [], 'found_at': []}
        for mode in ATTACK_MODES
    }
    checkpoints_ref = None

    # ─── PHASE 2 : Iterations (capture + attaque) ──────────
    SN_F4 = "44203120394d36433030312039323039"

    for iteration in range(NB_ITERATIONS):
        print(f"\n{'='*60}\n  ITÉRATION {iteration + 1} / {NB_ITERATIONS}\n{'='*60}")

        scope, target = None, None
        all_traces    = []
        all_plaintexts = []

        try:
            scope, target = setup_scope(PLATFORM, sn=SN_F4)

            # ── Capture des 8 configs ──────────────────────
            for i, cfg in enumerate(CONFIGS):
                config_seed = SEED + i + (iteration * 100)
                print(f"\n  [{cfg['name']}] Flash + Capture... (seed={config_seed})")

                src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.{ext}")
                dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.{ext}")
                shutil.copy2(src, dst)
                program_target(scope, target, PLATFORM)

                traces, plaintexts = capture_traces(scope, target, N=N_TRACES_PER_CONFIG, seed=config_seed)

                if traces is not None and len(traces) > 0:
                    all_traces.append(traces)
                    all_plaintexts.append(plaintexts)
                else:
                    print(f"  [ERREUR] Échec capture config {cfg['name']}.")

        finally:
            if scope:  scope.dis()
            if target: target.dis()

        if not all_traces:
            print("[ERREUR CRITIQUE] Aucune trace capturée — itération ignorée.")
            continue

        # ── Fusion et mélange ─────────────────────────────
        traces_total     = np.concatenate(all_traces)
        plaintexts_total = np.concatenate(all_plaintexts)
        total_n          = len(traces_total)

        np.random.seed(SEED + iteration)
        idx = np.arange(total_n)
        np.random.shuffle(idx)
        traces_shuffled     = traces_total[idx]
        plaintexts_shuffled = plaintexts_total[idx]
        print(f"\n[MÉLANGE] {total_n} traces fusionnées et mélangées.")

        # ── Attaques CPA et DPA sur le même dataset ───────
        for mode in ATTACK_MODES:
            print(f"\n{'─'*55}")
            print(f"  [{mode}] Analyse — Itération {iteration + 1}/{NB_ITERATIONS}")
            print(f"{'─'*55}")

            # find_min_traces_streaming : accumulateurs incrémentaux
            # → pas de matrice 80000×5000 en mémoire, pic ~1.8 GB
            checkpoints, corr_correct, corr_best, found_at, r_hist = find_min_traces_streaming(
                traces_shuffled, plaintexts_shuffled,
                attack_mode=mode, batch_size=2000)

            if checkpoints_ref is None:
                checkpoints_ref = checkpoints

            results[mode]['ranks_history'].append(r_hist)
            results[mode]['corr_correct'].append(corr_correct)
            results[mode]['corr_best'].append(corr_best)
            results[mode]['found_at'].append(found_at)

            best_key, max_corr, _, _ = attack_fn(traces_shuffled, plaintexts_shuffled)
            print_summary(
                f"Spatial Hiding [{mode}] (Iter {iteration + 1})",
                PLATFORM, best_key, max_corr, found_at, total_n
            )

    # ─── PHASE 3 : Graphes moyens par mode d'attaque ───────
    if checkpoints_ref is None:
        print("[ERREUR] Aucun résultat à tracer.")
    else:
        print(f"\n{'='*60}\n  PHASE 3 : GRAPHES FINAUX\n{'='*60}")

        for mode in ATTACK_MODES:
            r = results[mode]
            if not r['ranks_history']:
                print(f"[{mode}] Aucun résultat.")
                continue

            # Corrélation moyenne
            avg_corr_correct = np.mean(r['corr_correct'], axis=0)
            avg_corr_best    = np.mean(r['corr_best'],    axis=0)

            # Entropie de devinette
            rmatrix    = np.array(r['ranks_history'])
            mean_ranks = np.mean(rmatrix, axis=0)
            min_ranks  = np.min(rmatrix,  axis=0)
            max_ranks  = np.max(rmatrix,  axis=0)

            # Nombre de fois où la clé a été retrouvée
            found_list = [f for f in r['found_at'] if f is not None]
            found_info = (f"Clé trouvée {len(found_list)}/{NB_ITERATIONS} fois"
                          f" — moy. {int(np.mean(found_list))} traces"
                          if found_list else f"Clé non trouvée sur {NB_ITERATIONS} runs")
            print(f"[{mode}] {found_info}")

            plot_min_traces(
                checkpoints_ref, avg_corr_correct, avg_corr_best, None,
                title=f'[{PLATFORM}] {mode} ({NB_ITERATIONS} runs) — Spatial Hiding Fusionné',
                filename=f'{mode.lower()}_avg_{PLATFORM}_{CONFIG_NAME}.png'
            )

            plot_guessing_entropy(
                checkpoints_ref, mean_ranks, min_ranks, max_ranks,
                title=f'[{PLATFORM}] Entropie {mode} ({NB_ITERATIONS} runs) — Spatial Hiding Fusionné',
                filename=f'guessing_entropy_{mode.lower()}_avg_{PLATFORM}_{CONFIG_NAME}.png'
            )

        print("\n[TERMINÉ] Tous les graphes ont été générés dans results/")