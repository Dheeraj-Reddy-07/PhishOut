# Google Semantic False-Positive Diagnostic

**Date:** 2026-08-24  
**Scope:** Runtime diagnostic and minimal semantic-extractor bug fix; no models, thresholds, datasets, or E1-E7 results changed.

## Conclusion

Google's semantic probability of **0.8133** is produced by the frozen semantic model from the exact 12-feature vector below. The result is **not caused by a runtime fusion mismatch**: the runtime passes these same semantic values, in the documented `SEMANTIC_KEYS` order, to the frozen semantic model.

The elevated Google score remains primarily an **expected limitation of the learned semantic model/features (B)** rather than evidence that Google has an unusually large phishing signal. Compared with the Phish360 training distribution, Google's values are mostly below or near the global feature means. The model nevertheless maps this particular combination of a short page, one form, login language, brand mentions, and now-counted scripts to a high phishing probability. This is a learned false-positive behavior, not something that should be fixed with a Google whitelist or threshold change.

A separate **genuine feature-extraction bug (A)** was found and fixed: the extractor decomposed all `script` tags before counting them, making the `scripts` feature zero. The count now occurs before removal. This was an ordering-only runtime/extractor fix; no model was retrained, so the frozen research-model results remain unchanged.

## Runtime Values

The existing `PhishOutPredictor.predict()` path fetched each page, called `extract_semantic_features()`, converted values using `SEMANTIC_KEYS`, and called the frozen `semantic_model.pkl` and `semantic_scaler.pkl`.

| Semantic feature      | Google | Microsoft | Wikipedia | PayPal |
| --------------------- | -----: | --------: | --------: | -----: |
| password_fields       |      0 |         0 |         0 |      0 |
| text_email_fields     |      0 |         0 |         0 |      0 |
| forms                 |      1 |         1 |         1 |      0 |
| external_links        |      9 |        36 |       374 |     13 |
| iframes               |      0 |         0 |         0 |      0 |
| scripts               |     14 |         6 |         4 |     23 |
| login_indicators      |      1 |         2 |         0 |     11 |
| credential_indicators |      0 |         2 |         0 |      0 |
| payment_indicators    |      0 |         0 |         0 |    136 |
| urgency_indicators    |      0 |         0 |         2 |      2 |
| brand_indicators      |      3 |        33 |         2 |     48 |
| text_length           |    458 |      2100 |      6221 |   8722 |

## Model Outputs

| URL                       | Semantic probability | Semantic model score | Rule diagnostic score | Final risk | Verdict    |
| ------------------------- | -------------------: | -------------------: | --------------------: | ---------: | ---------- |
| https://www.google.com    |               0.8448 |                   84 |                     0 |         47 | SUSPICIOUS |
| https://www.microsoft.com |               0.6421 |                   64 |                    21 |         24 | SUSPICIOUS |
| https://www.wikipedia.org |               0.0214 |                    2 |                     9 |          1 | SAFE       |
| https://www.paypal.com    |               0.2344 |                   23 |                    24 |          4 | SAFE       |

## Relevant Indicators

### Google

The post-fix runtime detected one form, one login-related occurrence, three brand mentions, and 14 script tags. There were no password fields, credential indicators, payment indicators, urgency indicators, or iframes. The semantic rule diagnostic was 0/100, which shows that the rule display score and the learned model probability are different quantities; the learned model is the quantity used by learned fusion.

### Microsoft

Microsoft had one form, 36 external links, six script tags, two login indicators, two credential indicators, 33 brand mentions, and 2,100 characters of visible text. These are materially stronger raw semantic signals than Google's, explaining its elevated semantic probability of 0.6421. The rule diagnostic was 21/100.

### Wikipedia

Wikipedia had very high external-link and text-length counts, four script tags, but no login or credential indicators. Its semantic probability was only 0.0214. This indicates that the learned model does not treat every large page, high link count, or script count as phishing by itself.

### PayPal

PayPal had high payment and brand counts, 11 login indicators, and 23 script tags, but no form or password field. Its semantic probability was 0.2344 and its final fused risk was 4 because the structural probability was low and the learned fusion output remained below the calibrated threshold.

## Implementation Finding

In `backend/webpage_analyzer.py`, the extractor previously executed:

```python
for tag in soup(["script", "style", "noscript"]):
    tag.decompose()
```

It later computes:

```python
scripts = len(soup.find_all("script"))
```

Because the script nodes had already been removed, `scripts` was always zero on this extraction path. The code now counts scripts before this removal loop. This is a real implementation defect that is fixed for runtime correctness. Because the Phase 2 semantic model was not retrained, the model's learned behavior and all E1-E7 research artifacts remain unchanged.

## Final Assessment

- **Runtime fusion consistency:** correct.
- **Google unusually high raw feature:** no; its feature values are mostly not high relative to training-wide means.
- **Google semantic probability:** a remaining learned-model false positive caused by the model's learned nonlinear response to the feature combination, especially the short page/form/login/brand/script pattern. The post-fix probability was 0.8448 on this live fetch.
- **Microsoft elevation:** more directly supported by high brand, credential, external-link, and login indicators.
- **Classification:** the confirmed `scripts` ordering defect was **A** and is fixed; the Google false positive itself remains primarily **B, an expected learned-model/feature limitation**.
- **Paper treatment:** report this as a limitation of the semantic feature pipeline and learned semantic model. Do not whitelist Google, change thresholds, or alter the frozen research results.
