"""
run_config_G.py — Config G : S-Box en CCM, Pile (Stack) en CCM
Clé AES : SRAM | S-Box : CCM | Variables temporaires (Pile) : CCM
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import *

# ─── Paramètres ───────────────────────────────────────────
PLATFORM   = 'CW308_STM32F4'
EXTRA_OPTS = 'USE_CCM_SBOX -DUSE_CCM_STACK'
N_TRACES   = 50
CONFIG     = 'G'
ATTACK_MODE= 'CPA'               # ← 'CPA' ou 'DPA'
LABEL      = 'Config G — S-Box CCM, Pile CCM, Clé SRAM'
# ──────────────────────────────────────────────────────────

_attack_fn = cpa_attack_full if ATTACK_MODE == 'CPA' else dpa_attack_full
print(f"[MODE] Attaque sélectionnée : {ATTACK_MODE}")

if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)

    compile_firmware(PLATFORM, EXTRA_OPTS)
    scope, target = setup_scope(PLATFORM)

    try:
        program_target(scope, target, PLATFORM)
        traces, plaintexts = capture_traces(scope, target, N=N_TRACES)
    finally:
        scope.dis()
        target.dis()

    plot_trace(traces,
               title=f'{LABEL} ({PLATFORM})',
               filename=f'trace_{PLATFORM}_config{CONFIG}.png',
               ylim=(-0.5, 0.5))

    # 6. Analyse nombre minimum de traces
    checkpoints, corr_correct, corr_best, found_at, r_hist = find_min_traces(
        traces, plaintexts, attack_fn=_attack_fn)

    plot_min_traces(checkpoints, corr_correct, corr_best, found_at,
                    title=f'{ATTACK_MODE} — {LABEL} ({PLATFORM})',
                    filename=f'{ATTACK_MODE.lower()}_{PLATFORM}_config{CONFIG}.png')
                    
    plot_guessing_entropy(checkpoints, r_hist, r_hist, r_hist,
                          title=f'Entropie de Devinette ({ATTACK_MODE}) — {LABEL} ({PLATFORM})',
                          filename=f'guessing_entropy_{ATTACK_MODE.lower()}_{PLATFORM}_config{CONFIG}.png')

    # 7. CPA complète sur toutes les traces (16 octets)
    best_key, max_corr, _, _ = _attack_fn(traces, plaintexts)
    print_summary(LABEL, PLATFORM, best_key, max_corr, found_at, N_TRACES)
