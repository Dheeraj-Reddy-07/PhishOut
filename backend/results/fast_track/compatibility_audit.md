# Compatibility Audit
## Structural_V2
Features used: 32 URL-based features (e.g., url_length, hostname_length, special_char_count).
Valid mutations: UrlRemoveSuspiciousKeywordsMutation (1).
Invalid mutations: All HTML mutations (14).

## Semantic_V4
Features used: 384-dimensional text embeddings from HTML.
Valid mutations: All HTML mutations (14).
Invalid mutations: URL mutations (1) (unless the URL text is explicitly rendered in the HTML body, but strictly speaking, URL changes alone don't change the semantic payload).

## Baseline_V3 & Hardened_V4
Features used: URL features + HTML semantic embeddings.
Valid mutations: ALL mutations (15).