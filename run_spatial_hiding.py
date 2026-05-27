"""
run_spatial_hiding.py — Test de la contre-mesure Spatial Hiding (Approche Tuteur)
Ce script fusionne et mélange les traces de 8 configurations différentes
pour simuler un attaquant faisant face au Spatial Hiding.
"""
import sys, os, shutil
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import *

# ─── Paramètres ───────────────────────────────────────────
PLATFORM    = 'CW308_STM32F3'     # ou CW308_STM32F4
N_TRACES_PER_CONFIG = 10         # N traces par config (augmente à 500 pour le rapport final)
SEED        = 42                  # Seed fixe pour avoir les mêmes plaintexts sur chaque config
ATTACK_MODE = 'CPA'               # ← 'CPA' ou 'DPA'
LABEL       = 'Contre-mesure Hiding Spatial (Dataset Fusionné)'
CONFIG_NAME = 'SPATIAL_HIDING_MERGED'
# ──────────────────────────────────────────────────────────

_attack_fn = cpa_attack_full if ATTACK_MODE == 'CPA' else dpa_attack_full
print(f"[MODE] Attaque sélectionnée : {ATTACK_MODE}")

CONFIGS = [
    {'name': 'A', 'extra': ''},
    {'name': 'B', 'extra': 'USE_CCM_KEY'},
    {'name': 'C', 'extra': 'USE_CCM'},
    {'name': 'D', 'extra': 'USE_CCM_SBOX'},
    {'name': 'E', 'extra': 'USE_CCM_STACK'},
    {'name': 'F', 'extra': 'USE_CCM_KEY -DUSE_CCM_STACK'},
    {'name': 'G', 'extra': 'USE_CCM_SBOX -DUSE_CCM_STACK'},
    {'name': 'H', 'extra': 'USE_CCM -DUSE_CCM_STACK'},
]

if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 1. Compilation des 8 firmwares (Phase 1)
    print(f"\n{'='*60}")
    print(f"  PHASE 1 : COMPILATION DES 8 CONFIGURATIONS")
    print(f"{'='*60}")
    
    ext = "bin" if PLATFORM == 'CW308_STM32F4' else "hex"
    
    for cfg in CONFIGS:
        compile_firmware(PLATFORM, cfg['extra'])
        src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.{ext}")
        dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.{ext}")
        shutil.copy2(src, dst)
        print(f"[COMPILE] Binaire config {cfg['name']} sauvegardé.")

    # 2. Capture des traces pour les 8 configs (Phase 2)
    print(f"\n{'='*60}")
    print(f"  PHASE 2 : CAPTURE DES TRACES")
    print(f"{'='*60}")
    
    scope, target = setup_scope(PLATFORM)
    all_traces = []
    all_plaintexts = []
    
    try:
        for cfg in CONFIGS:
            print(f"\n  [{cfg['name']}] Flash + Capture...")
            # Restaure le bon binaire avant le flash
            src = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}_config{cfg['name']}.{ext}")
            dst = os.path.join(FW_PATH, f"simpleserial-aes-{PLATFORM}.{ext}")
            shutil.copy2(src, dst)
            
            program_target(scope, target, PLATFORM)
            
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES_PER_CONFIG, seed=SEED)
            all_traces.append(traces)
            all_plaintexts.append(plaintexts)
            
    finally:
        scope.dis()
        target.dis()
    #debug print the matrixes
    for i in range(len(all_plaintexts)):
        print(f"[PLAINTEXTS] Config {i}: {all_plaintexts[i]}")
    
    for i in range(len(all_traces)):
        print(f"[TRACES] Config {i}: {all_traces[i]}")
    # 3. Fusion et mélange (Phase 3)
    print(f"\n{'='*60}")
    print(f"  PHASE 3 : FUSION ET MÉLANGE DES DONNÉES")
    print(f"{'='*60}")
    
    traces_total = np.concatenate(all_traces)
    plaintexts_total = np.concatenate(all_plaintexts)
    
    total_traces_count = len(traces_total)
    print(f"[FUSION] Taille totale : {total_traces_count} traces (8 x {N_TRACES_PER_CONFIG}).")
    
    indices = np.arange(total_traces_count)
    np.random.shuffle(indices)
    
    traces_shuffled = traces_total[indices]
    plaintexts_shuffled = plaintexts_total[indices]
    print("[MÉLANGE] Shuffle appliqué avec succès.")

    # 4. Analyse et Graphes sur le dataset fusionné (Phase 4)
    print(f"\n{'='*60}")
    print(f"  PHASE 4 : ATTAQUE CPA/DPA SUR DATASET FUSIONNÉ")
    print(f"{'='*60}")

    plot_trace(traces_shuffled, title=f'{LABEL} ({PLATFORM})', filename=f'trace_{PLATFORM}_{CONFIG_NAME}.png', ylim=(-0.5, 0.5))

    checkpoints, corr_correct, corr_best, found_at, r_hist = find_min_traces(traces_shuffled, plaintexts_shuffled, attack_fn=_attack_fn)

    plot_min_traces(checkpoints, corr_correct, corr_best, found_at,
                    title=f'{ATTACK_MODE} — {LABEL} ({PLATFORM})',
                    filename=f'{ATTACK_MODE.lower()}_{PLATFORM}_{CONFIG_NAME}.png')
                    
    plot_guessing_entropy(checkpoints, r_hist, r_hist, r_hist,
                          title=f'Entropie de Devinette ({ATTACK_MODE}) — {LABEL} ({PLATFORM})',
                          filename=f'guessing_entropy_{ATTACK_MODE.lower()}_{PLATFORM}_{CONFIG_NAME}.png')

    best_key, max_corr, _ , _ = _attack_fn(traces_shuffled, plaintexts_shuffled)
    print_summary(LABEL, PLATFORM, best_key, max_corr, found_at, total_traces_count)
