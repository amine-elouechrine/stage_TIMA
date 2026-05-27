"""
cpa_core.py — Module partagé pour les attaques CPA sur AES-128
Usage : importé par run_config_A/B/C/D.py
"""

from sys import platform
import os
import sys
import subprocess
import numpy as np
import matplotlib
matplotlib.use('Agg')  # pas de fenêtre graphique
import matplotlib.pyplot as plt
import numpy as np


# ─────────────────────────────────────────────────────────
# Chemin vers chipwhisperer
# ─────────────────────────────────────────────────────────
FW_PATH = os.path.join(os.path.dirname(__file__), "firmware", "mcu", "simpleserial-aes")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

import time
import chipwhisperer as cw

# S-Box AES pour le modèle de fuite
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

SBOX = np.array(SBOX)
HW_TABLE = np.array([bin(x).count('1') for x in range(256)], dtype=np.uint8)
KNOWN_KEY = bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])


def hamming_weight(x):
    return bin(x).count('1')

# ─────────────────────────────────────────────────────────
# Compilation firmware
# ─────────────────────────────────────────────────────────
def compile_firmware(platform, extra_opts=""):
    """Compile le firmware pour la plateforme donnée avec nettoyage forcé."""
    
    # 1. Nettoyage obligatoire pour forcer la recompilation 
    clean_cmd = f"make PLATFORM={platform} clean"
    print(f"\n[COMPILE] Nettoyage : {clean_cmd}")
    subprocess.run(clean_cmd, shell=True, cwd=FW_PATH, capture_output=True)

    # 2. Construction de la commande (On utilise EXTRA_OPTS, SANS le -D)
    cmd = f"make PLATFORM={platform} CRYPTO_TARGET=TINYAES128C SS_VER=SS_VER_2_1"
    
    if extra_opts:
        # Le Makefile de CW ajoutera le -D tout seul sur les mots simples,
        # mais on peut aussi y glisser des arguments g++ ou linker.
        opts = extra_opts
        if "USE_CCM_STACK" in extra_opts:
            if platform == 'CW308_STM32F3':
                opts += " -Wl,--defsym=_estack=0x10002000"
            elif platform == 'CW308_STM32F4':
                opts += " -Wl,--defsym=_estack=0x10010000"
                
        cmd += f' EXTRA_OPTS="{opts}"' 
        
    cmd += " -j"
    
    print(f"[COMPILE] Build : {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=FW_PATH,
                             capture_output=False, text=True)
                             
    if result.returncode != 0:
        raise RuntimeError(f"Compilation échouée !")
    print("[COMPILE] OK")

    
# ─────────────────────────────────────────────────────────
# Setup ChipWhisperer
# ─────────────────────────────────────────────────────────
def setup_scope(platform):
    """Connecte et configure le scope CW avec des paramètres fixes."""
    scope = cw.scope()
    target = cw.target(scope, cw.targets.SimpleSerial2)
    # default_setup() gère correctement tio1/tio2/hs2/clock pour F3 et F4
    scope.default_setup()

    # On n'override PAS les pins IO ici (ça perturbe l'entrée bootloader)
    # On fixe seulement les paramètres d'acquisition pour avoir une échelle identique
    scope.adc.samples = 5000
    scope.adc.offset = 0
    scope.gain.gain = 45
    scope.gain.mode = "high"

    print(f"[SCOPE] Connecté. Gain={scope.gain.gain}, Samples={scope.adc.samples}")
    return scope, target


# ─────────────────────────────────────────────────────────
# Programmation firmware
# ─────────────────────────────────────────────────────────
def program_target(scope, target, platform):
    """Flashe le firmware sur la cible."""
    bin_file = os.path.join(FW_PATH,
                             f"simpleserial-aes-{platform}.bin")
    hex_file = os.path.join(FW_PATH,
                             f"simpleserial-aes-{platform}.hex")

    if platform == 'CW308_STM32F4':
        # F4 : flash automatique via st-flash (ST-Link V2)
        if not os.path.exists(bin_file):
            raise FileNotFoundError(f"Fichier BIN introuvable : {bin_file}")
        cmd = ["st-flash", "write", bin_file, "0x08000000"]
        print(f"[FLASH F4] {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[FLASH F4] STDERR: {result.stderr.strip()}")
                raise RuntimeError("st-flash a échoué !")
        except Exception as e:
            print(f"[FLASH F4] Erreur lors du flash : {e}")
            raise
        # Reset hardware pour que le chip démarre le nouveau firmware
        scope.io.nrst = 'low'
        time.sleep(0.1)
        scope.io.nrst = 'high_z'
        time.sleep(1.0)
        print("[FLASH F4] OK — chip resetté, firmware démarré.")
    else:
        # F3 : programmé via CW (UART bootloader)
        if not os.path.exists(hex_file):
            raise FileNotFoundError(f"Fichier HEX introuvable : {hex_file}")
        # Reset + délai pour que le chip entre bien en mode bootloader
        scope.io.nrst = 'low'
        time.sleep(0.1)
        scope.io.nrst = 'high_z'
        time.sleep(0.5)
        prog = cw.programmers.STM32FProgrammer
        cw.program_target(scope, prog, hex_file)

    print(f"[FLASH] {platform} → OK")


# ─────────────────────────────────────────────────────────
# Capture des traces
# ─────────────────────────────────────────────────────────
def capture_traces(scope, target, N=200, seed=None):
    """Capture N traces et retourne (traces, plaintexts).
    seed : si fourni, les plaintexts sont déterministes (même seed = même séquence).
    """
    from tqdm import trange
    import time

    if seed is not None:
        rng = np.random.default_rng(seed)
        # Stocker des numpy arrays (pas bytes) → s'empilent en tableau 2D dans cpa_attack
        all_texts = [rng.integers(0, 256, 16, dtype=np.uint8) for _ in range(N + 50)]
        key, pt_idx = KNOWN_KEY, 0
        text = all_texts[pt_idx]; pt_idx += 1
        print(f"[CAPTURE] Seed={seed} — plaintexts déterministes")
    else:
        ktp = cw.ktp.Basic()
        key, text = ktp.next()
        all_texts, pt_idx = None, 0

    trace_array = []
    textin_array = []

    # Flush + set_key avec retries
    target.flush()
    time.sleep(0.2)

    for attempt in range(5):
        try:
            target.set_key(key)
            print(f"[CAPTURE] Clé envoyée (tentative {attempt+1})")
            break
        except Exception as e:
            print(f"[CAPTURE] set_key tentative {attempt+1}/5 échouée — attente 1s...")
            target.flush()
            time.sleep(1.0)
    else:
        raise RuntimeError("Impossible d'envoyer la clé au target ! Vérifie les connexions.")

    consecutive_timeouts = 0
    MAX_CONSECUTIVE = 10  # stoppe si 10 timeouts de suite → target mort

    i = 0
    pbar = trange(N, desc='Capture traces')
    while len(trace_array) < N:
        pbar.update(0)  # actualise l'affichage
        scope.arm()
        target.simpleserial_write('p', text)

        ret = scope.capture()
        if ret:
            consecutive_timeouts += 1
            print(f"\n  [WARN] Timeout trace {i} ({consecutive_timeouts} consécutifs)")

            if consecutive_timeouts >= MAX_CONSECUTIVE:
                print(f"\n  [ERREUR] {MAX_CONSECUTIVE} timeouts consécutifs — target mort ?")
                print(f"  Arrêt. {len(trace_array)} traces capturées sur {N}.")
                break

            # Resync : flush + délai + relancer la clé
            target.flush()
            time.sleep(0.5)
            target.set_key(key)
            if all_texts is not None:
                text = all_texts[pt_idx % len(all_texts)]; pt_idx += 1
            else:
                key, text = ktp.next()
            i += 1
            continue

        consecutive_timeouts = 0  # reset le compteur si succès

        try:
            _ = target.simpleserial_read('r', 16)
        except Exception:
            pass

        trace_array.append(scope.get_last_trace())
        textin_array.append(text)
        pbar.update(1)

        if all_texts is not None:
            text = all_texts[pt_idx % len(all_texts)]; pt_idx += 1
        else:
            key, text = ktp.next()
        i += 1

    pbar.close()
    traces = np.array(trace_array)
    plaintexts = np.array(textin_array)
    print(f"[CAPTURE] {len(traces)} traces valides capturées")
    return traces, plaintexts


# ─────────────────────────────────────────────────────────
# Attaque CPA
# ─────────────────────────────────────────────────────────
def _compute_leakage_model(plaintexts_byte: np.ndarray) -> np.ndarray:
    """HW(SBOX[plaintext_byte XOR key_guess]) pour chaque 
    trace et chaque candidat clé. → (n_traces, 256)"""
    n_traces = len(plaintexts_byte)
    # Matrice avec des zeros
    leakage_matrix = np.zeros((n_traces, 256), dtype=np.float64)
    for trace_idx, plaintext_byte in enumerate(plaintexts_byte):
        for key_guess in range(256):
            sbox_output = SBOX[plaintext_byte ^ key_guess]
            
            # Hamming weight
            leakage_matrix[trace_idx, key_guess] = hamming_weight(sbox_output)       
    return leakage_matrix

def _pearson_all_keys(leakage_hypotheses: np.ndarray, traces: np.ndarray) -> np.ndarray:
    """
    Corrélation de Pearson .
    Input: leakage_hyptheses : les traces enregistre' avec la cle candidate
           traces: les traces enregistre' avec la vraie cle'
    Output: Matrice de (256, n_samples)
    Compare 256 hypothèses contre tous les échantillons.

    """
    # Centrer les matrices
    centered_hypotheses = leakage_hypotheses - leakage_hypotheses.mean(axis=0, keepdims=True)
    centered_traces = traces - traces.mean(axis=0, keepdims=True)#compute mean column-wise

    # Produit matriciel
    covariance = centered_hypotheses.T @ centered_traces

    # Calcul des écarts-types
    std_hypotheses = np.sqrt(np.sum(centered_hypotheses ** 2, axis=0))
    std_traces = np.sqrt(np.sum(centered_traces ** 2, axis=0))

    # Dénominateur et protection contre la division par 0
    standard_deviation = np.outer(std_hypotheses, std_traces)

    #remplacer tout les 0 avec 1e-10
    standard_deviation[standard_deviation == 0] = 1e-10 # super small value 

    # Retourne directement la matrice de taille (256, n_samples)
    return np.abs(covariance / standard_deviation)

def _rank_and_expected(max_corr_per_key: np.ndarray, expected_key: int) -> tuple[float, int]:
    """Rang et corrélation de la vraie clé parmi les 256 candidats.
       Input:
            max_corr_per_key: vecteur de correlation de taille (256)
            expected_key: clé qu'on cherche
       Output:
            corr_expected_key: corrélation de la vraie clé
            vraie cle = cle qu'on cherche ( expected key ) ->
            rank: rang de la vraie clé
    """
    #expected key est la clé qu'on cherche
    corr_expected_key = float(max_corr_per_key[expected_key])#float car max_corr_per_key est un array numpy
    #trier les valeurs de correlation par ordre decroissant
    rank_expected_key = int((max_corr_per_key > corr_expected_key).sum() + 1)
    return corr_expected_key, rank_expected_key


def cpa_attack(traces: np.ndarray, plaintexts: np.ndarray, byte: int = 0, known_key=None) -> tuple:
    """
    CPA sur un octet spécifique de la clé .
    Retourne (best_key_byte, max_correlation, rank, expected_correlation)
    """
    if known_key is None:
        known_key = KNOWN_KEY

    plaintext_bytes    = plaintexts[:, byte].astype(np.uint8)
    leakage = _compute_leakage_model(plaintext_bytes)
    #les corrélations de une cle avec tout les instants de la trace
    abs_correlation    = _pearson_all_keys(leakage, traces)
    #pour chaque cle garder max correlation
    max_corr_per_key = abs_correlation.max(axis=1)
    #pas la valeure maximale mais la position du maximum
    best_key         = int(np.argmax(max_corr_per_key))
    #la valeur du meilleur score trouvé
    max_corr         = float(max_corr_per_key[best_key])

    corr_expected_key, rank = _rank_and_expected(max_corr_per_key, known_key[byte])

    return best_key, max_corr, rank, corr_expected_key

def cpa_attack_full(traces, plaintexts, known_key=None):
    """
    Lance le CPA indépendamment sur les 16 octets de la clé AES.
    Retourne les listes contenant la clé reconstruite et les métriques de validation.
    """
    # Listes pour accumuler les résultats des 16 itérations
    recovered_key_bytes = []
    best_correlations = []
    true_key_ranks = []
    true_key_correlations = []
    
    # On boucle sur les 16 octets (de 0 à 15)
    for byte_index in range(16):
        # Déballage explicite des 4 résultats de l'attaque sur un seul octet
        found_byte, max_correlation, rank, true_key_corr = cpa_attack(
            traces, 
            plaintexts, 
            byte=byte_index, 
            known_key=known_key
        )
        #found_byte c'est le l'octet qui a ete retourner comme hypothese de la cle 
        # Sauvegarde des résultats
        recovered_key_bytes.append(found_byte)
        best_correlations.append(max_correlation)
        true_key_ranks.append(rank)#the position of the true key between every other key
        true_key_correlations.append(true_key_corr)#the correlation score of the true key
        
    return recovered_key_bytes, best_correlations, true_key_ranks, true_key_correlations

# =============================================================
# DPA ATTACK MODULE
# =============================================================
TARGET_BIT = 0



def _compute_difference_of_means(plaintext_bytes: np.ndarray, traces: np.ndarray, bit: int = 0) -> np.ndarray:
    """Moteur Statistique DPA."""
    #initialize the dpa matrix with zeros
    dpa_matrix = np.zeros((256, traces.shape[1]), dtype=np.float64)
    for key_guess in range(256):
        bits = (SBOX[plaintext_bytes ^ key_guess] >> bit) & 1#select the column corresponding to the current key guess
        #group the traces into two groups based on the bit value
        group_1 = traces[bits == 1]
        group_0 = traces[bits == 0]
        
        if len(group_1) == 0 or len(group_0) == 0:
            continue
            
        mean_1 = group_1.mean(axis=0)
        mean_0 = group_0.mean(axis=0)
        dpa_matrix[key_guess] = np.abs(mean_1 - mean_0)
    return dpa_matrix

def dpa_attack(traces: np.ndarray, plaintexts: np.ndarray, byte: int = 0, known_key=None) -> tuple:
    """Wrapper DPA 1 octet (Signature identique à cpa_attack)"""
    if known_key is None:
        known_key = KNOWN_KEY

    plaintext_bytes = plaintexts[:, byte].astype(np.uint8)
    #selection of the wanted plaintexte
    #selection_matrix = _compute_selection_matrix(plaintext_bytes)
    #mean difference of the traces
    dpa_curves = _compute_difference_of_means(plaintext_bytes, traces)
    
    max_dpa_per_key = dpa_curves.max(axis=1)#axis=1 means take the maximum for each row
    best_key = int(np.argmax(max_dpa_per_key))
    max_dpa = float(max_dpa_per_key[best_key])#the value of the spike
    
    true_key_dpa, rank = _rank_and_expected(max_dpa_per_key, known_key[byte])
    
    return best_key, max_dpa, rank, true_key_dpa

def dpa_attack_full(traces, plaintexts, known_key=None):
    """Wrapper DPA 16 octets (Signature identique à cpa_attack_full)"""
    best_keys, max_dpas, ranks, true_key_dpas = [], [], [], []
    for b in range(16):
        bk, md, rnk, tkd = dpa_attack(traces, plaintexts, byte=b, known_key=known_key)
        best_keys.append(bk)
        max_dpas.append(md)
        ranks.append(rnk)
        true_key_dpas.append(tkd)
    return best_keys, max_dpas, ranks, true_key_dpas


# ─────────────────────────────────────────────────────────
# Analyse du nombre minimum de traces
# ─────────────────────────────────────────────────────────
def find_min_traces(traces, plaintexts, known_key=KNOWN_KEY, attack_fn=None):
    """
    Teste l'attaque (CPA ou DPA) avec un nombre croissant de traces sur les 16 OCTETS.
    attack_fn : fonction d'attaque à utiliser (cpa_attack_full ou dpa_attack_full).
                Par défaut : cpa_attack_full.
    """
    if attack_fn is None:
        attack_fn = cpa_attack_full
    n_total = len(traces)
    checkpoints = []
    n = 2
    checkpoints = []
    facteur_croissance = 1.5  # Ajustez ceci : 1.2 pour plus de points, 2.0 pour moins de points

    while n <= n_total:
        checkpoints.append(n)
        
        # On multiplie par le facteur pour avoir une croissance exponentielle
        prochain_n = int(n * facteur_croissance)
        
        # Sécurité : on force une augmentation d'au moins 2 à chaque étape
        # Cela évite les boucles infinies au début (ex: int(2 * 1.1) = 2)
        if prochain_n < n + 2:
            n += 2
        else:
            n = prochain_n

    print("checkpoints list:  ", checkpoints)

    if not checkpoints or checkpoints[-1] != n_total:
        checkpoints.append(n_total) 

    corr_correct = []
    corr_best = []
    ranks_history = []
    found_at = None

    for n in checkpoints:
        t_sub = traces[:n] #traces until n
        p_sub = plaintexts[:n] #traces until n 
        print("attack with " + n + " traces")
        # Pass known_key down
        best_ks, max_cs, ranks, expected_cs = attack_fn(t_sub, p_sub, known_key=known_key)
        corr_correct.append(np.mean(expected_cs))
        corr_best.append(np.mean(max_cs))
        ranks_history.append(np.mean(ranks)) 
        
        if list(best_ks) == list(known_key) and found_at is None:
            found_at = n

    return checkpoints, corr_correct, corr_best, found_at, ranks_history


# ─────────────────────────────────────────────────────────
# Graphes
# ─────────────────────────────────────────────────────────
def plot_trace(traces, title, filename, ylim=(-0.5, 0.5)):
    """Trace la moyenne des traces avec une échelle fixe."""
    fig, ax = plt.subplots(figsize=(12, 4))
    mean_trace = traces.mean(axis=0)
    ax.plot(mean_trace, color='steelblue', linewidth=0.5)
    ax.set_title(title, fontsize=14)
    ax.set_xlabel("Échantillon")
    ax.set_ylabel("Amplitude (V)")
    ax.set_ylim(ylim)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, filename)
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[PLOT] Sauvegardé : {path}")


def plot_min_traces(checkpoints, corr_correct, corr_best, found_at,
                    title, filename):
    """Trace la corrélation en fonction du nombre de traces."""
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(checkpoints, corr_correct, 'b-o', markersize=3,
            label='Clé correcte (moyenne)')
    ax.plot(checkpoints, corr_best, 'r--', linewidth=1,
            label='Meilleur candidat (moyenne)')
    if found_at:
        ax.axvline(found_at, color='green', linestyle=':', linewidth=2,
                   label=f'Clé (16o) trouvée à {found_at} traces')
    ax.set_title(title, fontsize=13)
    ax.set_xlabel("Nombre de traces")
    ax.set_ylabel("Corrélation max")
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, filename)
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[PLOT] Sauvegardé : {path}")

def plot_guessing_entropy(checkpoints, mean_ranks, min_ranks, max_ranks, title, filename):
    """Trace l'Entropie de Devinette (Rang) avec la zone min/max (pointillés de ton prof)."""
    fig, ax = plt.subplots(figsize=(10, 5))
    
    # Courbe moyenne (pleine)
    ax.plot(checkpoints, mean_ranks, 'b-', linewidth=2, label="Rang Moyen")
    
    # Pointillés (min/max)
    ax.plot(checkpoints, min_ranks, 'r--', linewidth=1, label="Meilleur Cas (Min)")
    ax.plot(checkpoints, max_ranks, 'g--', linewidth=1, label="Pire Cas (Max)")
    
    # Zone remplie pour plus de visibilité
    ax.fill_between(checkpoints, min_ranks, max_ranks, color='blue', alpha=0.1)

    ax.set_title(title, fontsize=13)
    ax.set_xlabel("Nombre de traces")
    ax.set_ylabel("Entropie de Devinette (Rang, 1 = Gagné)")
    ax.set_ylim(0.5, max(128, int(np.max(max_ranks)*1.1)))
    ax.set_yscale('symlog')  # Echelle log souvent plus lisible pour les rangs
    ax.grid(True, alpha=0.3)
    ax.legend()
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, filename)
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[PLOT] Guessing Entropy sauvegardé : {path}")


def plot_guessing_entropy_comparison(checkpoints, ranks_data, configs, platform, attack_mode=""):
    """
    Trace l'Entropie de Devinette (Rang moyen) pour toutes les configurations
    sur un seul graphe — analogue à plot_comparison() pour la corrélation.
    """
    colors = ['blue', 'orange', 'green', 'red', 'purple', 'brown', 'pink', 'gray']

    fig, ax = plt.subplots(figsize=(12, 6))

    for i, cfg in enumerate(configs):
        k = cfg['name']
        data = ranks_data.get(k, [])
        if not data:
            continue
        rmatrix = np.array(data)
        mean_ranks = np.mean(rmatrix, axis=0)
        min_ranks  = np.min(rmatrix,  axis=0)
        max_ranks  = np.max(rmatrix,  axis=0)

        c = colors[i % len(colors)]
        ax.plot(checkpoints, mean_ranks,
                color=c, linewidth=2, marker='o', markersize=3,
                label=cfg['label'])
        ax.fill_between(checkpoints, min_ranks, max_ranks,
                        color=c, alpha=0.08)

    ax.axhline(1, color='black', linestyle=':', linewidth=1, label='Rang 1 (clé trouvée)')
    
    mode_str = f" ({attack_mode})" if attack_mode else ""
    ax.set_title(f'Entropie de Devinette{mode_str} — Toutes configs ({platform})', fontsize=14)
    ax.set_xlabel('Nombre de traces')
    ax.set_ylabel('Rang moyen de la vraie clé (1 = trouvée)')
    ax.set_yscale('symlog')
    ax.legend(loc='upper right', fontsize=9)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()

    mode_str_file = f"_{attack_mode.lower()}" if attack_mode else ""
    path = os.path.join(RESULTS_DIR, f'guessing_entropy_comparison{mode_str_file}_{platform}.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"\n[PLOT] Guessing Entropy comparaison : {path}")


def print_summary(config_name, platform, best_keys, max_corrs, found_at, n_total):
    """Affiche un résumé dans le terminal."""
    ok = "✅" if list(best_keys) == list(KNOWN_KEY) else "❌"
    
    key_str = " ".join([f"{k:02x}" for k in best_keys])
    expected_str = " ".join([f"{k:02x}" for k in KNOWN_KEY])
    
    print(f"\n{'='*50}")
    print(f"  Config : {config_name} | Platform : {platform}")
    print(f"  Clé trouvée : {key_str}")
    print(f"  (attendu)   : {expected_str} {ok}")
    print(f"  Corrélation moy : {np.mean(max_corrs):.4f}")
    if found_at:
        print(f"  Minimum de traces pour clé COMPLÈTE : {found_at} / {n_total}")
    else:
        print(f"  ⚠️  Clé complète non trouvée avec {n_total} traces")
    print(f"{'='*50}\n")

def plot_trace_differences(all_traces, platform):
    """Calcule et trace la différence entre la Config A (SRAM) et les autres."""
    if len(all_traces) < 2:
        return
        
    baseline_res = all_traces[0]
    baseline_mean = baseline_res['traces'].mean(axis=0)
    
    n_comparisons = len(all_traces) - 1
    fig, axes = plt.subplots(n_comparisons, 1, figsize=(14, 3*n_comparisons), sharex=True)
    if n_comparisons == 1:
        axes = [axes]
        
    for i, res in enumerate(all_traces[1:]):
        ax = axes[i]
        current_mean = res['traces'].mean(axis=0)
        diff = baseline_mean - current_mean
        ax.plot(diff, color='purple', linewidth=0.8)
        ax.set_title(f"Différence : [{baseline_res['label']}]  MOINS  [{res['label']}]", fontsize=11)
        ax.set_ylabel("Diff (V)")
        
        # On définit une échelle Y serrée pour bien voir les différences minimes
        max_diff = np.max(np.abs(diff))
        limit = max(0.01, max_diff * 1.2)  # au moins 10mV ou 120% du max
        ax.set_ylim(-limit, limit)
        ax.grid(True, alpha=0.4, linestyle='--')
        
    axes[-1].set_xlabel("Échantillon (Temps)")
    plt.suptitle(f"Empreinte de la mémoire CCM (Analyse Différentielle) — {platform}", fontsize=14, y=1.02)
    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, f'traces_diff_{platform}.png')
    plt.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Graphe des différences sauvegardé : {path}")
