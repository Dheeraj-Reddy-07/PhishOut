import re
from bs4 import BeautifulSoup, NavigableString, Tag

def extract_semantic_text(html: str) -> str:
    """
    Extracts visible text and structural context from HTML.
    Instead of just joining tokens, it annotates important elements:
    e.g., [TITLE], [INPUT], [BUTTON], [LINK].
    """
    if not html:
        return ""
        
    soup = BeautifulSoup(html, "html.parser")
    
    # Remove invisible/noisy tags
    for tag in soup(["script", "style", "noscript", "meta", "link", "svg", "path"]):
        tag.decompose()
        
    extracted = []
    
    if soup.title and soup.title.string:
        extracted.append(f"[TITLE] {soup.title.string.strip()}")
        
    # Find all meaningful text and interactive elements
    body = soup.body if soup.body else soup
    
    for element in body.descendants:
        if isinstance(element, NavigableString):
            text = str(element).strip()
            if text and element.parent.name not in ["script", "style", "button", "a"]:
                extracted.append(text)
        elif isinstance(element, Tag):
            if element.name == "input":
                t = element.get("type", "text")
                if t in ["hidden", "radio", "checkbox", "submit"]:
                    continue
                placeholder = element.get("placeholder", "")
                name = element.get("name", "")
                label = placeholder or name or t
                extracted.append(f"[INPUT {t}] {label}")
            elif element.name == "button" or (element.name == "input" and element.get("type") == "submit"):
                val = element.get("value", "") or element.get_text(strip=True) or "Submit"
                extracted.append(f"[BUTTON] {val}")
            elif element.name == "a":
                text = element.get_text(strip=True)
                if text:
                    extracted.append(f"[LINK] {text}")
                    
    # Clean up excessive whitespace and duplicates sequentially
    raw_text = " ".join(extracted)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    
    # Truncate to a reasonable length for the transformer model (e.g. 1000 words ~ 4000 chars)
    # SentenceTransformer max sequence length is typically 256/512 tokens.
    words = raw_text.split()
    if len(words) > 400:
        raw_text = " ".join(words[:400])
        
    return raw_text
