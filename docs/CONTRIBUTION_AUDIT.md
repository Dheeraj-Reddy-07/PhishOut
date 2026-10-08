# CONTRIBUTION AUDIT

### Base Paper
**"An Optimized Machine Learning Framework for Phishing Website Detection Integrating Feature Robustness and Adversarial Resilience Ranking" (IEEE, 2025)**
- Extracted structural URL features.
- Applied ±5% numerical perturbations for robustness testing.
- Ranked feature robustness.

### PhishOut Additions

**IMPLEMENTED CONTRIBUTION**
1. **Hybrid Architecture:** Combined 32 structural features with 19 semantic HTML features. (Implemented and evaluated)
2. **Learned Score-Level Fusion:** Implemented a logistic regression meta-learner to fuse probabilities, replacing arbitrary weights. (Implemented and evaluated)
3. **Context-Aware False Positive Reduction:** Mined hard-negatives (legitimate auth pages) to fix semantic false positives, dropping the Hard-Negative FPR from 4.0% to 2.0% in V3. (Implemented and evaluated)
4. **Webpage-Level Adversarial Attacks (E5-E7):** Replaced numerical perturbations with actual HTML/URL mutations (Visible-text obfuscation, URL-query padding, etc.). (Implemented and evaluated)
5. **Adversarial Training & Generalization:** Conducted adversarial training (E6) and proved evasion reduction on unseen attacks (E7). (Implemented and evaluated)

**CLAIMED BUT NOT EXPERIMENTALLY PROVEN**
- *None.* All claimed contributions in `PROJECT_PLAN.md` have corresponding experimental artifacts (E1-E7).
