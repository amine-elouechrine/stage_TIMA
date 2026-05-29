"""
run_f3_10x_final_plot.py — Automatisation F3 (DPA + CPA) - Graphe Global
"""
import sys, os
import numpy as np  # 🚀 Indispensable pour calculer la moyenne, min et max
sys.path.insert(0, os.path.dirname(__file__))

# ─── Configuration ────────────────────────────────────────
PLATFORM   = 'CW308_STM32F3'     
SERIAL_SN  = '50203120324136503130352030313031' # ID unique F3
N_TRACES   = 100000
CONFIG     = 'SPATIAL_HIDING'
LABEL      = 'Contre-mesure Hiding Spatial'

ITERATIONS = 1  # Nombre d'itérations
# ──────────────────────────────────────────────────────────

# 🚀 LE PATCH MAGIQUE (Monkey Patching) pour ChipWhisperer
import chipwhisperer as cw
_original_scope = cw.scope

def _patched_scope(*args, **kwargs):
    kwargs['sn'] = SERIAL_SN 
    return _original_scope(*args, **kwargs)

cw.scope = _patched_scope

# Import de ta bibliothèque métier APRÈS le patch
from cpa_core import *

if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print(f"\n[{PLATFORM}] 1. Compilation...")
    compile_firmware(PLATFORM, '')

    print(f"[{PLATFORM}] 2. Connexion au scope {SERIAL_SN}...")
    scope, target = setup_scope(PLATFORM)

    # ─── Variables pour stocker les résultats des 10 itérations ───
    all_r_hist_DPA = []
    all_r_hist_CPA = []
    checkpoints_saved = None

    try:
        print(f"[{PLATFORM}] 3. Flash du firmware (une seule fois)...")
        program_target(scope, target, PLATFORM)

        # ─── BOUCLE DES 10 ITÉRATIONS (Capture + Calculs Uniquement) ───
        for iteration in range(1, ITERATIONS + 1):
            print(f"\n" + "="*50)
            print(f"[{PLATFORM}] DÉBUT DE L'ITÉRATION {iteration}/{ITERATIONS}")
            print(f"="*50)

            print(f"[{PLATFORM}] 4. Capture des {N_TRACES} traces...")
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES)

            # Optionnel : Tu peux garder ou enlever la sauvegarde de la trace brute ici
            plot_trace(traces, title=f'{LABEL} ({PLATFORM}) - Iter {iteration}', 
                       filename=f'trace_{PLATFORM}_config{CONFIG}_iter{iteration}.png', ylim=(-0.5, 0.5))

            for ATTACK_MODE in ['DPA', 'CPA']:
                print(f"[{PLATFORM}] Calcul de l'attaque : {ATTACK_MODE}...")
                _attack_fn = cpa_attack_full if ATTACK_MODE == 'CPA' else dpa_attack_full

                # On récupère les données de cette itération
                checkpoints, corr_correct, corr_best, found_at, r_hist = find_min_traces(traces, plaintexts, attack_fn=_attack_fn)

                # On sauvegarde l'axe des X (le nombre de traces) une seule fois
                if checkpoints_saved is None:
                    checkpoints_saved = checkpoints

                # On stocke l'historique d'entropie (r_hist) dans la bonne liste
                if ATTACK_MODE == 'DPA':
                    all_r_hist_DPA.append(r_hist)
                else:
                    all_r_hist_CPA.append(r_hist)
                
    finally:
        scope.dis()
        target.dis()
        print(f"\n[{PLATFORM}] Connexion scope libérée.")

    # ─── GÉNÉRATION DES GRAPHIQUES FINAUX (Après les 10 itérations) ───
    print(f"\n[{PLATFORM}] Génération des graphiques globaux d'entropie...")

    for ATTACK_MODE, history_list in [('DPA', all_r_hist_DPA), ('CPA', all_r_hist_CPA)]:
        # Convertir la liste de listes en un tableau Numpy 2D
        hist_matrix = np.array(history_list)

        # Calculer la moyenne, le min et le max sur l'axe 0 (les colonnes)
        r_mean = np.mean(hist_matrix, axis=0)
        r_min  = np.min(hist_matrix, axis=0)
        r_max  = np.max(hist_matrix, axis=0)

        # On appelle ta fonction de dessin avec les vraies statistiques !
        plot_guessing_entropy(checkpoints_saved, r_mean, r_min, r_max,
                              title=f'Entropie de Devinette ({ATTACK_MODE}) — {LABEL} ({PLATFORM})',
                              filename=f'guessing_entropy_GLOBAL_{ATTACK_MODE.lower()}_{PLATFORM}_config{CONFIG}.png')

    print(f"\n[SUCCESS] Les {ITERATIONS} itérations sont terminées ! Graphiques finaux générés.")