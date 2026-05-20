# CPA Scripts — Analyse de Sécurité (CCM vs SRAM)

Ce dépôt contient une suite de scripts Python permettant de réaliser une **Correlation Power Analysis (CPA)** sur des implémentations AES-128 s'exécutant sur des microcontrôleurs STM32 (F3 et F4). L'objectif est de comparer la fuite d'information physique selon que les données sensibles (clé, S-Box, pile) sont placées en SRAM classique ou en **CCM (Core Coupled Memory)**.

## 🛠️ Prérequis

1. **Environnement ChipWhisperer** :
   ```bash
   source ~/.cwvenv/bin/activate
   ```
2. **Matériel** :
   - ChipWhisperer (Lite or Nano)
   - Target Board : CW308_STM32F3 ou CW308_STM32F4
3. **Outils système** (pour F4) : `st-flash` (ST-Link Tools).

## 🚀 Utilisation Rapide

### 1. Analyse d'une configuration spécifique
Chaque script `run_config_X.py` compile le firmware avec les flags appropriés, flashe la cible, capture les traces et génère les graphes d'analyse (Trace, CPA, Guessing Entropy).

```bash
python3 run_config_A.py  # Exemple pour la Config A (Baseline)
```

### 2. Comparaison de toutes les configurations
Pour comparer l'efficacité de la CCM sur une plateforme donnée :
- **STM32F3** : `python3 run_all.py`
- **STM32F4** : `python3 run_all_F4.py`

### 3. Benchmarking Statistique (Mode Expert)
Pour obtenir des métriques fiables (moyenne du nombre de traces pour casser la clé, évolution du rang), utilisez les scripts de benchmark :
- **STM32F3** : `python3 benchmark.py`
- **STM32F4** : `python3 benchmark_F4.py`

## ⚙️ Configurations Mémoire (CCM)

Le projet évalue 5 configurations majeures définies via `EXTRA_OPTS` lors de la compilation :

| Config | Description              | Octets sensibles  | `EXTRA_OPTS`    |
| :----: | ------------------------ | :---------------: | --------------- |
| **A**  | **Baseline (Tout SRAM)** |       Aucun       | (vide)          |
| **B**  | **Clé en CCM**           |      Clé AES      | `USE_CCM_KEY`   |
| **C**  | **Tout en CCM**          |    Clé + S-Box    | `USE_CCM`       |
| **D**  | **S-Box en CCM**         |       S-Box       | `USE_CCM_SBOX`  |
| **E**  | **Pile (Stack) en CCM**  | Variables locales | `USE_CCM_STACK` |

> [!IMPORTANT]
> La **Config E** déplace l'intégralité de la pile en CCM via des flags de linker spécifiques gérés automatiquement dans `cpa_core.py`.

## 📱 Changer de Plateforme

Pour basculer entre F3 et F4, modifiez la variable `PLATFORM` en haut des scripts :
```python
PLATFORM = 'CW308_STM32F3'  # ou 'CW308_STM32F4'
```

## 🔑 Benchmark Multi-Clés (Config A)

Ces scripts testent si la clé AES influe sur la résistance à la CPA, en fixant **Config A (Tout SRAM)** et en faisant varier la clé.

```bash
python3 benchmark_keys_F3.py   # STM32F3
python3 benchmark_keys_F4.py   # STM32F4
```

Chaque script effectue **10 runs** sur ces 6 clés :

|   Nom    | Description                   | Poids de Hamming |
| :------: | ----------------------------- | :--------------: |
|  `NIST`  | Clé de référence AES standard |        68        |
|  `ZERO`  | Tous les bits à 0             |        0         |
|   `FF`   | Tous les bits à 1             |       128        |
| `ALTERN` | Pattern `0xAA` alterné        |        64        |
| `ONEBIT` | Un seul bit actif             |        1         |
| `RANDOM` | Clé réaliste aléatoire        |       ~64        |

**Résultats générés :**
- `guessing_entropy_PLATFORM_configA_keyNAME.png` — Rang par clé
- `comparison_keys_PLATFORM_configA.png` — Comparaison globale

> [!IMPORTANT]
> La clé testée doit être **identique dans le firmware C et dans `cpa_core.py`**. Chaque changement de clé nécessite une recompilation et un re-flash du firmware.

## 📊 Résultats (Dossier `results/`)

- `trace_PLATFORM_configX.png` — Consommation de puissance
- `cpa_PLATFORM_configX.png` — Corrélation vs nombre de traces
- `guessing_entropy_PLATFORM_configX.png` — Évolution du rang de la clé
- `comparison_PLATFORM.png` — Comparaison du succès de l'attaque
- `traces_diff_PLATFORM.png` — Analyse différentielle (SRAM vs CCM)
- `comparison_keys_PLATFORM_configA.png` — Comparaison par clé

## 📂 Structure du Projet

- `cpa_core.py` : Cœur logique (capture, CPA, plotting, compilation)
- `run_config_*.py` : Scripts unitaires par configuration
- `benchmark.py` / `benchmark_F4.py` : Benchmark statistique multi-configs
- `benchmark_keys_F3.py` / `benchmark_keys_F4.py` : Benchmark multi-clés
- `run_all.py` / `run_all_F4.py` : Comparaison globale des configurations
