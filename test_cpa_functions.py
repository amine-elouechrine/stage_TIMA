import numpy as np
from scipy.spatial.distance import cdist
from cpa_core import (
    _compute_leakage_model,_pearson_all_keys 
)
def validate_leakage_model():
    # --- Valeur connue 1 : plaintext=0x00, key_guess=0x00 ---
    plaintext_test = np.array([0x09])
    result = _compute_leakage_model(plaintext_test)
    #verifier la taille
    assert result.shape == (1, 256), \
        f"Shape incorrecte: {result.shape}"
    assert result[0, 0] == 1, \
        f"Attendu 4 pour plaintext=0x00, key=0x00, obtenu {result[0, 0]}"

    # --- Valeur connue 2 : plaintext=0x00, key_guess=0x01 ---
    # SBOX[0x00 XOR 0x01] = SBOX[0x01] = 0x7C = 0111 1100 → HW = 5
    assert result[0, 1] == 2, \
        f"Attendu 5 pour plaintext=0x00, key=0x01, obtenu {result[0, 1]}"

    # --- Valeur connue 3 : plaintext=0xFF, key_guess=0xFF ---
    # SBOX[0xFF XOR 0xFF] = SBOX[0x00] = 0x63 → HW = 4
    plaintext_test2 = np.array([0xFF])
    result2 = _compute_leakage_model(plaintext_test2)
    assert result2[0, 0xFF] == 4, \
        f"Attendu 4 pour plaintext=0xFF, key=0xFF, obtenu {result2[0, 0xFF]}"

    # --- Valeur connue 4 : plaintext=0x01, key_guess=0x01 ---
    # SBOX[0x01 XOR 0x01] = SBOX[0x00] = 0x63 → HW = 4
    plaintext_test3 = np.array([0x01])
    result3 = _compute_leakage_model(plaintext_test3)
    assert result3[0, 0x01] == 4, \
        f"Attendu 4 pour plaintext=0x01, key=0x01, obtenu {result3[0, 0x01]}"

    # --- Vérification des bornes : HW toujours entre 0 et 8 ---
    plaintexts_all = np.arange(256, dtype=np.uint8)
    result_all = _compute_leakage_model(plaintexts_all)
    assert result_all.shape == (256, 256), \
        f"Shape incorrecte: {result_all.shape}"
    assert result_all.min() >= 0 and result_all.max() <= 8, \
        f"HW hors bornes [0,8]: min={result_all.min()}, max={result_all.max()}"

    print("Toutes les validations sont passées !")

import numpy as np

def test_pearson_full_matrix():
    """
    Prouve que notre fonction vectorisée génère EXACTEMENT la même matrice globale
    que NumPy, sur toutes les hypothèses et tous les échantillons en même temps.
    """
    print("="*60)
    print(" TEST D'ÉQUIVALENCE MATRICIELLE (CUSTOM vs NUMPY) ")
    print("="*60)
    
    # Création de fausses données 
    n_traces = 500
    n_keys = 256
    n_samples = 50 
    
    dummy_leakage = np.random.rand(n_traces, n_keys)    # (500, 256)
    dummy_traces = np.random.rand(n_traces, n_samples)  # (500, 50)
    
    print(f"[+] Dimensions : {n_traces} traces | {n_keys} hypothèses | {n_samples} échantillons")

    # 1. NOTRE FONCTION CUSTOM  
    our_matrix = _pearson_all_keys(dummy_leakage, dummy_traces)

    # 2. NUMPY CORRCOEF
    combined_data = np.hstack([dummy_leakage, dummy_traces])
    full_np_corr = np.corrcoef(combined_data, rowvar=False)
    
    # Extraction du bloc cible
    numpy_matrix = np.abs(full_np_corr[:n_keys, n_keys:])

    # 3. VALIDATION
    is_numpy_identical = np.allclose(our_matrix, numpy_matrix, atol=1e-10)
    max_error_numpy = np.max(np.abs(our_matrix - numpy_matrix))


    
    print("\n--- RÉSULTATS ---")
    print(f"Équivalence avec NumPy validée ? : {' OUI' if is_numpy_identical else ' NON'} (Marge d'erreur max : {max_error_numpy:.2e})")
    # ==========================================================
    # TEST 2 : PROPRIÉTÉ MATHÉMATIQUE (Vecteur vs Lui-même = 1)
    # ==========================================================
    
    # On passe la même matrice en hypothèse et en trace
    self_corr_matrix = _pearson_all_keys(dummy_leakage, dummy_leakage)
    
    # On extrait la diagonale (qui compare la colonne 0 avec 0, 1 avec 1, etc.)
    diagonal_values = np.diag(self_corr_matrix)
    
    # On vérifie si toutes les valeurs de la diagonale sont égales à 1.0
    is_property_validated = np.allclose(diagonal_values, 1.0, atol=1e-10)
    
    print("\n--- TEST DE LA PROPRIÉTÉ (A vs A = 1) ---")
    print(f"Propriété validée sur la diagonale ? : {' OUI' if is_property_validated else ' NON'}")


# Lancer le test
test_pearson_full_matrix()
validate_leakage_model()
