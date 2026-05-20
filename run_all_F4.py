"""
run_all_F4.py — Lance toutes les configurations sur STM32F4 (64KB CCM)
⚠️  Nécessite : ST-Link V2 connecté + carte F4 sur la CW308
Connecte le scope CW UNE SEULE FOIS → même échelle pour tous les graphes
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from cpa_core import *
import matplotlib.pyplot as plt

# ─── Paramètres ───────────────────────────────────────────
PLATFORM = 'CW308_STM32F4'   # ← F4 seulement — Utiliser run_all.py pour la F3
N_TRACES = 30
SEED     = 42   # seed fixe → mêmes plaintexts à chaque run

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
# ──────────────────────────────────────────────────────────

def plot_comparison(all_results):
    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ['blue', 'orange', 'green', 'red', 'purple', 'brown', 'pink', 'gray']
    for i, res in enumerate(all_results):
        ax.plot(res['checkpoints'], res['corr_correct'],
                color=colors[i], linewidth=2, marker='o', markersize=2,
                label=res['label'])
        if res['found_at']:
            ax.axvline(res['found_at'], color=colors[i],
                       linestyle='--', linewidth=1, alpha=0.5)
    ax.set_title(f'CPA — Corrélation vs Nombre de traces ({PLATFORM})', fontsize=14)
    ax.set_xlabel('Nombre de traces')
    ax.set_ylabel('Corrélation (clé correcte)')
    ax.legend(loc='lower right')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, f'comparison_{PLATFORM}.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"\n[PLOT] Comparaison : {path}")


def plot_traces_comparison(all_traces):
    fig, axes = plt.subplots(len(all_traces), 1,
                              figsize=(14, 3*len(all_traces)),
                              sharex=True, sharey=True)
    colors = ['steelblue', 'darkorange', 'forestgreen', 'crimson', 'purple', 'brown', 'pink', 'gray']
    for i, (ax, res) in enumerate(zip(axes, all_traces)):
        ax.plot(res['traces'].mean(axis=0), color=colors[i], linewidth=0.5)
        ax.set_title(res['label'], fontsize=11)
        ax.set_ylabel('Amplitude (V)')
        ax.set_ylim(-0.5, 0.5)
        ax.grid(True, alpha=0.2)
    axes[-1].set_xlabel('Échantillon')
    plt.suptitle(f'Traces de puissance — {PLATFORM}', fontsize=13, y=1.01)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, f'traces_comparison_{PLATFORM}.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Traces: {path}")


if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("\n" + "="*60)
    print(" PHASE 1 : COMPILATION (F4)")
    print("="*60)
    for cfg in CONFIGS:
        compile_firmware(PLATFORM, cfg['extra'])

    print("\n" + "="*60)
    print(" PHASE 2 : CONNEXION SCOPE")
    print("="*60)
    scope, target = setup_scope(PLATFORM)

    all_results = []
    all_traces_data = []

    try:
        for cfg in CONFIGS:
            print(f"\n{'─'*50}")
            print(f"  Lancement : {cfg['label']}")
            print(f"{'─'*50}")

            # 1. COMPILATION (écrasera l'ancien .hex, mais ce n'est pas grave)
            print(f"[INFO] Compilation avec l'option : {cfg['extra']}")
            compile_firmware(PLATFORM, cfg['extra'])

            # 2. FLASHAGE (ST-Link V2)
            print("[INFO] Flashage de la cible F4...")
            program_target(scope, target, PLATFORM)

            # 3. CAPTURE
            traces, plaintexts = capture_traces(scope, target, N=N_TRACES, seed=SEED)

            plot_trace(traces,
                       title=f"{cfg['label']} ({PLATFORM})",
                       filename=f"trace_{PLATFORM}_config{cfg['name']}.png",
                       ylim=(-0.5, 0.5))

            # Analyse min traces sur 16 octets
            checkpoints, corr_correct, corr_best, found_at, r_hist = find_min_traces(traces, plaintexts)

            plot_min_traces(checkpoints, corr_correct, corr_best, found_at,
                            title=f"CPA — {cfg['label']} ({PLATFORM})",
                            filename=f"cpa_{PLATFORM}_config{cfg['name']}.png")

            from cpa_core import plot_guessing_entropy
            plot_guessing_entropy(checkpoints, r_hist, r_hist, r_hist,
                                  title=f"Entropie de Devinette — {cfg['label']} ({PLATFORM})",
                                  filename=f"guessing_entropy_{PLATFORM}_config{cfg['name']}.png")

            # CPA complète (16 octets)
            best_key, max_corr, _ , _= cpa_attack_full(traces, plaintexts)
            print_summary(cfg['label'], PLATFORM, best_key, max_corr,
                          found_at, N_TRACES)

            all_results.append({
                'label': cfg['label'],
                'checkpoints': checkpoints,
                'corr_correct': corr_correct,
                'found_at': found_at,
                'best_key': best_key,
                'max_corr': max_corr,
            })
            all_traces_data.append({'label': cfg['label'], 'traces': traces})

    finally:
        scope.dis()
        target.dis()
        print("\n[INFO] Scope déconnecté.")

    print("\n" + "="*60)
    print(" PHASE 3 : GRAPHES COMPARATIFS")
    print("="*60)
    plot_comparison(all_results)
    plot_traces_comparison(all_traces_data)
    plot_trace_differences(all_traces_data, PLATFORM)

    print("\n" + "="*60)
    print(f"  RÉSUMÉ FINAL — {PLATFORM}")
    print("="*60)
    print(f"{'Config':<35} {'Clé complète':<14} {'Corrélation moy':<18} {'Min traces'}")
    print("-"*85)
    for res in all_results:
        ok = "✅" if list(res['best_key']) == list(KNOWN_KEY) else "❌"
        found = str(res['found_at']) if res['found_at'] else "N/A"
        mean_corr = np.mean(res['max_corr'])
        print(f"  {res['label']:<33} {ok:<14} {mean_corr:.4f}             {found}")
    print("="*60)
    print(f"\nRésultats dans : {RESULTS_DIR}/")
