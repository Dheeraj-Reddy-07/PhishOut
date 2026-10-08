# FINAL SYSTEM DEFINITION

FINAL PRODUCT: V3 (`phish360_v3_learned_fusion` with 51 features)
FINAL RESEARCH MODEL: Phase 2 / V2 (`phish360_v2_learned_fusion` with 47 features). This is the model used for the E1-E7 adversarial evaluations (F1=94.26%).
BASELINE MODEL: Structural-only model (32 features)
DATASET: Phish360 (10,634 deduplicated samples)
FINAL FEATURES: 32 structural + 19 semantic (for V3) / 15 semantic (for V2)
FINAL ADVERSARIAL METHOD: Feature-level ±5% perturbation (E3) and HTML-level transformations like Visible-text obfuscation (E5-E7).
FINAL AUTHORITATIVE RESULTS:
- Production V3 F1: 96.53% (Hard-Negative FPR: 2.0%)
- Adversarial Evasion (E5): Max evasion of 5.42% under visible-text obfuscation.
- Adversarial Training (E6): Evasion reduced to 4.39%.
- Unseen Generalization (E7): Unseen percent-encoding evasion reduced to 0.18%.

The production backend (`/phishout/scan`), React dashboard, and Chrome extension all use **V3**. 
The E1-E7 artifacts and tables reflect the **Phase 2 (V2)** model.

### HISTORICAL / SUPERSEDED
- `models/phish360_v4*`: Directories for a "V4" model exist in the backend but are not integrated into the predictor, not documented in the project plan, and superseded by the V3 production candidate.
- Legacy PhreshPhish dataset (250 URLs).
