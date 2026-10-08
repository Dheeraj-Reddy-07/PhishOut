import re
import random
from bs4 import BeautifulSoup
from attacker.webpage_state import WebPageState
from attacker.mutations import Mutation

class HtmlParaphraseCredentialTextMutation(Mutation):
    def __init__(self):
        super().__init__("html_paraphrase_credentials", "Replaces credential keywords (e.g. password, login) with synonyms.")
        self.synonyms = {
            r"\bpassword\b": "passcode",
            r"\blogin\b": "authenticate",
            r"\bsign in\b": "access account",
            r"\busername\b": "user ID"
        }
        
    def is_applicable(self, state: WebPageState) -> bool:
        if not super().is_applicable(state): return False
        text = state.current_html.lower()
        return any(re.search(pattern, text) for pattern in self.synonyms.keys())
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        html = new_state.current_html
        for pattern, replacement in self.synonyms.items():
            html = re.sub(pattern, replacement, html, flags=re.IGNORECASE)
        new_state.current_html = html
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlTextToImageMutation(Mutation):
    def __init__(self):
        super().__init__("html_text_to_image", "Removes critical credential text and replaces it with an image tag.")
        
    def is_applicable(self, state: WebPageState) -> bool:
        return super().is_applicable(state) and "password" in state.current_html.lower()
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, 'html.parser')
        # Find elements containing password
        for tag in soup.find_all(['p', 'span', 'label', 'div', 'h1', 'h2']):
            if tag.string and "password" in tag.string.lower():
                tag.string = ""
                img = soup.new_tag("img", src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
                tag.append(img)
                break
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlAddIframeMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_iframe", "Injects an iframe pointing to a benign site.")
        
    def is_applicable(self, state: WebPageState) -> bool:
        return super().is_applicable(state)
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, 'html.parser')
        if soup.body:
            iframe = soup.new_tag("iframe", src="https://en.wikipedia.org", style="width:0;height:0;border:0;border:none;")
            soup.body.append(iframe)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlPrependMassivePaddingMutation(Mutation):
    def __init__(self):
        super().__init__("html_prepend_massive_padding", "Prepends thousands of words at the top of the body to push credentials past text extraction cutoffs.")
        self.words = ["terms", "conditions", "privacy", "policy", "information", "service", "copyright", "reserved", "contact", "about"]
        
    def is_applicable(self, state: WebPageState) -> bool:
        return super().is_applicable(state) and len(state.current_html) < 200000
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, 'html.parser')
        if soup.body:
            padding_text = " ".join(random.choices(self.words, k=5000))
            div = soup.new_tag("div", style="display:none;")
            div.string = padding_text
            soup.body.insert(0, div)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state
