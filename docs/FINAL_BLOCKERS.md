# FINAL BLOCKERS

### CRITICAL
- **Narrative Alignment on Models (V2 vs V3):** The production API correctly runs V3 (F1=96.53%), but the final E1-E7 tables and `FINAL_RESULTS.md` report metrics based on the Phase 2 (V2) baseline. This is scientifically valid (as E1-E7 were conducted prior to V3's specific UI/False Positive optimizations), but the final paper *must* explicitly clarify this distinction to avoid metric contradictions. 

### IMPORTANT
- **V4 Artifact Cleanup:** Stray `phish360_v4*` directories exist in `backend/models/`. These contradict the `PROJECT_PLAN.md` which states V3 is the final model. They must be explicitly documented as abandoned or removed to prevent reviewer confusion.

### OPTIONAL
- None.
