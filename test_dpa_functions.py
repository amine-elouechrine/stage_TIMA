"""
Script de test pour les fonctions DPA.
Stratégie : données synthétiques 100% contrôlées → résultat déterministe → assertions exactes.
"""

import numpy as np
import sys
import os

# ─────────────────────────────────────────────
# Import depuis cpa_core.py (même répertoire)
# ─────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cpa_core import (
    SBOX,
    HW_TABLE,
    KNOWN_KEY,
    _compute_selection_matrix as _compute_selection_matrix_hw,
    _compute_difference_of_means,
    dpa_attack,
)

# ─────────────────────────────────────────────
# Version bit unique (commentée dans cpa_core)
# On la redéfinit ici pour le Bloc 1
# ─────────────────────────────────────────────
def _compute_selection_matrix_bit(plaintexts_byte: np.ndarray, bit: int = 0) -> np.ndarray:
    """Version bit unique — utilisée uniquement dans les tests Bloc 1."""
    n_traces = len(plaintexts_byte)
    selection_matrix = np.zeros((n_traces, 256), dtype=np.uint8)
    for key_guess in range(256):
        sbox_out = SBOX[plaintexts_byte ^ key_guess]
        selection_matrix[:, key_guess] = (sbox_out >> bit) & 1
    return selection_matrix


# ═══════════════════════════════════════════════════
#  TESTS
# ═══════════════════════════════════════════════════

passed = 0
failed = 0

def ok(name):
    global passed
    passed += 1
    print(f"  [PASS] {name}")

def fail(name, detail=""):
    global failed
    failed += 1
    print(f"  [FAIL] {name}" + (f" → {detail}" if detail else ""))


# ───────────────────────────────────────────────────
# BLOC 1 : _compute_selection_matrix_bit
# ───────────────────────────────────────────────────
print("\n══ BLOC 1 : selection_matrix bit unique ══")

def test_sm_bit_shape():
    pt = np.array([0x00, 0x01, 0x02, 0x03], dtype=np.uint8)
    sm = _compute_selection_matrix_bit(pt, bit=0)
    assert sm.shape == (4, 256), f"shape={sm.shape}"
    ok("shape (4, 256)")

def test_sm_bit_valeurs_connues():
    """
    Pour key_guess=0 et plaintext=0x00 :
      sbox_out = SBOX[0x00 ^ 0x00] = SBOX[0] = 0x63 = 0b01100011
      bit 0 = 1  ← attendu
      bit 1 = 1  ← attendu
      bit 7 = 0  ← attendu
    """
    pt = np.array([0x00], dtype=np.uint8)
    sbox_val = int(SBOX[0])  # 0x63 = 99

    for b in range(8):
        sm = _compute_selection_matrix_bit(pt, bit=b)
        expected = (sbox_val >> b) & 1
        got = int(sm[0, 0])
        if got == expected:
            ok(f"SBOX[0x00^0x00]=0x{sbox_val:02x} bit{b}={expected}")
        else:
            fail(f"bit{b}", f"attendu={expected}, obtenu={got}")

def test_sm_bit_deux_groupes():
    """Avec assez de traces, les deux groupes (0 et 1) doivent exister."""
    rng = np.random.default_rng(42)
    pt = rng.integers(0, 256, size=200, dtype=np.uint8)
    sm = _compute_selection_matrix_bit(pt, bit=0)
    for kg in [0, 42, 128, 255]:
        col = sm[:, kg]
        if 0 in col and 1 in col:
            ok(f"deux groupes pour key_guess={kg}")
        else:
            fail(f"deux groupes pour key_guess={kg}", f"valeurs uniques={np.unique(col)}")

def test_sm_bit_binaire():
    """Toutes les valeurs doivent être 0 ou 1."""
    pt = np.arange(256, dtype=np.uint8)
    sm = _compute_selection_matrix_bit(pt, bit=0)
    uniq = np.unique(sm)
    if set(uniq).issubset({0, 1}):
        ok("valeurs strictement binaires {0,1}")
    else:
        fail("valeurs strictement binaires", f"trouvé={uniq}")

test_sm_bit_shape()
test_sm_bit_valeurs_connues()
test_sm_bit_deux_groupes()
test_sm_bit_binaire()


# ───────────────────────────────────────────────────
# BLOC 2 : _compute_selection_matrix (HW — version active)
# ───────────────────────────────────────────────────
print("\n══ BLOC 2 : selection_matrix poids de Hamming ══")

def test_sm_hw_shape():
    pt = np.array([0x00, 0x01, 0x02, 0x03], dtype=np.uint8)
    sm = _compute_selection_matrix_hw(pt)
    assert sm.shape == (4, 256)
    ok("shape (4, 256)")

def test_sm_hw_valeurs_autorisees():
    """Seules les valeurs -1, 0, 1 sont autorisées."""
    pt = np.arange(256, dtype=np.uint8)
    sm = _compute_selection_matrix_hw(pt)
    uniq = set(np.unique(sm))
    if uniq.issubset({-1, 0, 1}):
        ok("valeurs dans {-1, 0, 1}")
    else:
        fail("valeurs dans {-1, 0, 1}", f"trouvé={uniq}")

def test_sm_hw_hw_egal_4_ignore():
    """Un cas HW==4 doit rester à -1 (ignoré)."""
    found = False
    for p in range(256):
        for k in range(256):
            if HW_TABLE[SBOX[p ^ k]] == 4:
                pt = np.array([p], dtype=np.uint8)
                sm = _compute_selection_matrix_hw(pt)
                val = sm[0, k]
                if val == -1:
                    ok(f"HW=4 ignoré (p=0x{p:02x}, k=0x{k:02x}) → -1")
                else:
                    fail(f"HW=4 ignoré", f"valeur={val} au lieu de -1")
                found = True
                break
        if found:
            break

def test_sm_hw_coherence_groupe1():
    """Un cas HW>4 doit être à 1."""
    for p in range(256):
        for k in range(256):
            hw = HW_TABLE[SBOX[p ^ k]]
            if hw > 4:
                pt = np.array([p], dtype=np.uint8)
                sm = _compute_selection_matrix_hw(pt)
                if sm[0, k] == 1:
                    ok(f"HW={hw}>4 → groupe 1 (p=0x{p:02x}, k=0x{k:02x})")
                else:
                    fail("HW>4 → groupe 1", f"valeur={sm[0,k]}")
                return

def test_sm_hw_coherence_groupe0():
    """Un cas HW<4 doit être à 0."""
    for p in range(256):
        for k in range(256):
            hw = HW_TABLE[SBOX[p ^ k]]
            if hw < 4:
                pt = np.array([p], dtype=np.uint8)
                sm = _compute_selection_matrix_hw(pt)
                if sm[0, k] == 0:
                    ok(f"HW={hw}<4 → groupe 0 (p=0x{p:02x}, k=0x{k:02x})")
                else:
                    fail("HW<4 → groupe 0", f"valeur={sm[0,k]}")
                return

test_sm_hw_shape()
test_sm_hw_valeurs_autorisees()
test_sm_hw_hw_egal_4_ignore()
test_sm_hw_coherence_groupe1()
test_sm_hw_coherence_groupe0()


# ───────────────────────────────────────────────────
# BLOC 3 : _compute_difference_of_means
# ───────────────────────────────────────────────────
print("\n══ BLOC 3 : difference of means ══")

def test_dom_pic_parfait():
    """
    key=42 : groupe 1 = traces hautes, groupe 0 = traces basses → DoM = 1.0
    autres  : chaque groupe = moitié hautes + moitié basses     → DoM = 0.0
    """
    N = 100
    N_SAMPLES = 20
    REAL_KEY = 42
    LEAK_SAMPLE = 5

    traces = np.zeros((N, N_SAMPLES), dtype=np.float64)
    traces[:50, LEAK_SAMPLE] = 1.0

    sm = np.zeros((N, 256), dtype=np.int8)
    sm[:50, REAL_KEY] = 1
    sm[50:, REAL_KEY] = 0

    for kg in range(256):
        if kg == REAL_KEY:
            continue
        sm[0:25,  kg] = 1
        sm[25:50, kg] = 0
        sm[50:75, kg] = 1
        sm[75:,   kg] = 0

    dpa_matrix = _compute_difference_of_means(sm, traces)

    best_key    = int(np.argmax(dpa_matrix.max(axis=1)))
    best_sample = int(np.argmax(dpa_matrix[REAL_KEY]))
    best_val    = float(dpa_matrix[REAL_KEY, LEAK_SAMPLE])

    ok(f"pic sur la bonne clé ({REAL_KEY})") if best_key == REAL_KEY \
        else fail("pic sur la bonne clé", f"trouvé={best_key}")
    ok(f"pic au bon sample ({LEAK_SAMPLE})") if best_sample == LEAK_SAMPLE \
        else fail("pic au bon sample", f"trouvé={best_sample}")
    ok("valeur du pic = 1.0 exactement") if abs(best_val - 1.0) < 1e-10 \
        else fail("valeur du pic = 1.0", f"trouvé={best_val:.6f}")

def test_dom_groupes_vides_pas_crash():
    """Aucun groupe valide → pas de crash, matrice à zéro."""
    N = 10
    sm = np.full((N, 256), -1, dtype=np.int8)
    traces = np.random.rand(N, 5)
    try:
        dpa = _compute_difference_of_means(sm, traces)
        if np.all(dpa == 0):
            ok("groupes vides → pas de crash, matrice à zéro")
        else:
            fail("groupes vides", "matrice non nulle alors qu'aucun groupe")
    except Exception as e:
        fail("groupes vides → crash", str(e))

def test_dom_symetrie():
    """DoM = |mean1 - mean0| : inverser les labels doit donner le même résultat."""
    N, N_SAMPLES = 40, 10
    rng = np.random.default_rng(7)
    sm = rng.integers(0, 2, size=(N, 256), dtype=np.int8)
    traces = rng.random((N, N_SAMPLES))
    dpa1 = _compute_difference_of_means(sm, traces)
    dpa2 = _compute_difference_of_means(1 - sm, traces)
    if np.allclose(dpa1, dpa2, atol=1e-10):
        ok("symétrie : inverser les labels → même DoM")
    else:
        fail("symétrie", f"max diff={np.max(np.abs(dpa1 - dpa2)):.2e}")

def test_dom_shape():
    N, N_SAMPLES = 50, 15
    sm = np.zeros((N, 256), dtype=np.int8)
    sm[:25, :] = 1
    dpa = _compute_difference_of_means(sm, np.zeros((N, N_SAMPLES)))
    if dpa.shape == (256, N_SAMPLES):
        ok(f"shape de sortie (256, {N_SAMPLES})")
    else:
        fail("shape de sortie", f"trouvé={dpa.shape}")

test_dom_pic_parfait()
test_dom_groupes_vides_pas_crash()
test_dom_symetrie()
test_dom_shape()


# ───────────────────────────────────────────────────
# BLOC 4 : dpa_attack end-to-end
# ───────────────────────────────────────────────────
print("\n══ BLOC 4 : dpa_attack end-to-end ══")

def _make_synthetic_traces(real_key_byte, n_traces=500, n_samples=50, leak_sample=10, seed=0):
    """Traces synthétiques avec fuite HW réelle sur real_key_byte, zéro bruit."""
    rng = np.random.default_rng(seed)
    plaintexts = rng.integers(0, 256, size=(n_traces, 16), dtype=np.uint8)
    traces = np.zeros((n_traces, n_samples), dtype=np.float64)
    for i in range(n_traces):
        hw = HW_TABLE[SBOX[plaintexts[i, 0] ^ real_key_byte]]
        if hw > 4:
            traces[i, leak_sample] = 1.0
        elif hw < 4:
            traces[i, leak_sample] = -1.0
    return traces, plaintexts

def test_attack_retrouve_la_cle_sans_bruit():
    """Sans bruit, la bonne clé doit être en rang 1."""
    REAL_KEY = 0xAB
    traces, plaintexts = _make_synthetic_traces(REAL_KEY, n_traces=1000)
    best_key, max_dpa, rank, _ = dpa_attack(
        traces, plaintexts, byte=0, known_key=[REAL_KEY] + [0x00]*15
    )
    ok(f"bonne clé retrouvée : 0x{best_key:02x}") if best_key == REAL_KEY \
        else fail("bonne clé retrouvée", f"attendu=0x{REAL_KEY:02x}, trouvé=0x{best_key:02x}")
    ok(f"rang = 1") if rank == 1 \
        else fail("rang = 1", f"rang obtenu = {rank}")
    ok(f"max_dpa > 0 (pic : {max_dpa:.4f})") if max_dpa > 0 \
        else fail("max_dpa > 0", f"max_dpa={max_dpa}")

def test_attack_bruit_modere():
    """Avec bruit σ=0.3, la vraie clé doit rester en rang ≤ 3."""
    REAL_KEY = 0x2B
    traces, plaintexts = _make_synthetic_traces(REAL_KEY, n_traces=2000)
    traces += np.random.default_rng(99).normal(0, 0.3, size=traces.shape)
    _, _, rank, _ = dpa_attack(
        traces, plaintexts, byte=0, known_key=[REAL_KEY] + [0x00]*15
    )
    ok(f"bruit modéré → rang ≤ 3 (rang={rank})") if rank <= 3 \
        else fail("bruit modéré → rang ≤ 3", f"rang={rank}")

def test_attack_mauvaise_cle_rang_eleve():
    """Une fausse clé passée comme 'vraie' doit être mal classée."""
    REAL_KEY  = 0x2B
    WRONG_KEY = 0xFF
    traces, plaintexts = _make_synthetic_traces(REAL_KEY, n_traces=1000)
    best_key, _, rank, _ = dpa_attack(
        traces, plaintexts, byte=0, known_key=[WRONG_KEY] + [0x00]*15
    )
    ok(f"best_key est 0x{REAL_KEY:02x} (pas la fausse 0x{WRONG_KEY:02x})") if best_key == REAL_KEY \
        else fail("best_key est la vraie clé", f"best_key=0x{best_key:02x}")
    ok(f"fausse clé mal classée (rang={rank})") if rank > 1 \
        else fail("fausse clé mal classée", f"rang={rank}")

test_attack_retrouve_la_cle_sans_bruit()
test_attack_bruit_modere()
test_attack_mauvaise_cle_rang_eleve()


# ───────────────────────────────────────────────────
# RÉSUMÉ
# ───────────────────────────────────────────────────
total = passed + failed
print(f"\n{'═'*45}")
print(f"  Résultat : {passed}/{total} tests passés", end="")
print("  ✓ Tout est bon !" if failed == 0 else f"  ✗ {failed} test(s) échoué(s)")
print(f"{'═'*45}\n")