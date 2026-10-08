import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from bs4 import BeautifulSoup, NavigableString
from typing import Tuple, List, Callable
from .webpage_state import WebPageState

class Mutation:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        
    def is_applicable(self, state: WebPageState) -> bool:
        """Check if this mutation makes sense for the current state."""
        # Prevent runaway HTML growth
        if len(state.current_html) > 500000:
            return False
        return True
        
    def apply(self, state: WebPageState) -> WebPageState:
        """Returns a new WebPageState with the mutation applied."""
        raise NotImplementedError

# ---------------------------------------------------------
# URL MUTATIONS
# ---------------------------------------------------------

class UrlAddQueryMutation(Mutation):
    def __init__(self):
        super().__init__("url_add_benign_query", "Adds a benign query parameter to the URL.")
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        parts = list(urlsplit(new_state.current_url))
        query = dict(parse_qsl(parts[3]))
        query[f"tracking_id_{len(new_state.mutation_history)}"] = "abc123"
        parts[3] = urlencode(query)
        new_state.current_url = urlunsplit(parts)
        new_state.mutation_history.append(self.name)
        return new_state

class UrlAddFragmentMutation(Mutation):
    def __init__(self):
        super().__init__("url_add_fragment", "Adds a fragment hash to the URL.")
        
    def is_applicable(self, state: WebPageState) -> bool:
        return not urlsplit(state.current_url).fragment
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        parts = list(urlsplit(new_state.current_url))
        parts[4] = f"section_{len(new_state.mutation_history)}"
        new_state.current_url = urlunsplit(parts)
        new_state.mutation_history.append(self.name)
        return new_state

# ---------------------------------------------------------
# HTML MUTATIONS
# ---------------------------------------------------------

class HtmlAddBenignTextMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_benign_text", "Adds a hidden paragraph with benign text to dilute keyword density.")
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        body = soup.body if soup.body else soup
        p = soup.new_tag("p", style="display:none;", **{"aria-hidden": "true"})
        p.string = "This is a standard information page detailing accessibility and privacy policies for all users."
        body.append(p)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlAddDummyScriptMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_dummy_script", "Adds an empty script tag to alter text-to-script ratio.")
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        head = soup.head if soup.head else soup
        script = soup.new_tag("script", type="text/javascript")
        script.string = "// benign tracking script placeholder\nconsole.log('loaded');"
        head.append(script)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlAddExternalLinkMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_external_link", "Adds an invisible external link to alter external_links count.")
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        body = soup.body if soup.body else soup
        a = soup.new_tag("a", href="https://www.google.com/policies/privacy/", style="display:none;")
        a.string = "Privacy Policy"
        body.append(a)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlObfuscateTextMutation(Mutation):
    def __init__(self):
        super().__init__("html_obfuscate_text", "Replaces sensitive keywords with hyphenated versions to evade detection.")
        self.replacements = {
            "password": "pass-word",
            "verify": "ver-ify",
            "login": "log-in",
            "account": "acc-ount",
            "urgent": "ur-gent",
            "payment": "pay-ment"
        }
        self.pattern = re.compile("|".join(re.escape(word) for word in self.replacements.keys()), re.IGNORECASE)
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        for text_node in soup.find_all(string=True):
            if not isinstance(text_node, NavigableString):
                continue
            if text_node.parent.name in {"script", "style", "noscript"}:
                continue
            new_text = self.pattern.sub(lambda m: self.replacements[m.group().lower()], str(text_node))
            if new_text != str(text_node):
                text_node.replace_with(new_text)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlAddCosmeticDivMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_cosmetic_div", "Wraps body contents in a benign div container.")
        
    def is_applicable(self, state: WebPageState) -> bool:
        soup = BeautifulSoup(state.current_html, "html.parser")
        return soup.body is not None
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        wrapper = soup.new_tag("div", attrs={"class": "main-wrapper", "id": f"wrap_{len(new_state.mutation_history)}"})
        
        if soup.body:
            for child in list(soup.body.children):
                wrapper.append(child.extract())
            soup.body.append(wrapper)
        
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlInsertBenignMetaMutation(Mutation):
    def __init__(self):
        super().__init__("html_insert_benign_meta", "Inserts common benign meta tags like charset or viewport.")
        
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        head = soup.head if soup.head else soup
        meta = soup.new_tag("meta", attrs={"name": "theme-color", "content": "#ffffff"})
        head.insert(0, meta)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class UrlRemoveSuspiciousKeywordsMutation(Mutation):
    def __init__(self):
        super().__init__("url_remove_suspicious_keywords", "Replaces suspicious words in URL with benign synonyms.")
        self.replacements = {
            "login": "entry", "signin": "entry", "sign-in": "entry",
            "account": "user", "secure": "safe", "security": "safe",
            "verify": "check", "verification": "check", "confirm": "ok",
            "update": "edit", "banking": "finance", "password": "key",
            "credential": "auth", "authenticate": "auth"
        }
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        url = new_state.current_url
        parts = list(urlsplit(url))
        for old, new in self.replacements.items():
            parts[2] = parts[2].replace(old, new)
            parts[3] = parts[3].replace(old, new)
        new_state.current_url = urlunsplit(parts)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlObfuscateFormActionMutation(Mutation):
    def __init__(self):
        super().__init__("html_obfuscate_form_action", "Removes form action attribute and uses inline JS to submit.")
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        for form in soup.find_all("form"):
            if form.has_attr("action"):
                action = form["action"]
                del form["action"]
                form["onsubmit"] = f"this.action='{action}'; return true;"
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlSwapPasswordInputMutation(Mutation):
    def __init__(self):
        super().__init__("html_swap_password_input", "Replaces password inputs with text inputs styled to hide characters.")
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        for inp in soup.find_all("input", {"type": "password"}):
            inp["type"] = "text"
            inp["style"] = inp.get("style", "") + "; -webkit-text-security: disc; text-security: disc;"
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlAddMassiveBenignTextMutation(Mutation):
    def __init__(self):
        super().__init__("html_add_massive_benign_text", "Adds massive invisible benign text block to dilute densities.")
    def is_applicable(self, state: WebPageState) -> bool:
        if len(state.current_html) > 300000:
            return False
        return super().is_applicable(state)

    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        body = soup.body if soup.body else soup
        p = soup.new_tag("div", style="display:none;", **{"aria-hidden": "true"})
        p.string = " ".join(["This is a standard page outlining terms of service, accessibility, privacy policies, data protection guidelines, legal notices, and compliance information for users."] * 100)
        body.append(p)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state

class HtmlConvertLinksToButtonsMutation(Mutation):
    def __init__(self):
        super().__init__("html_convert_links_to_buttons", "Converts anchor tags to buttons with inline JS to drop external_links.")
    def apply(self, state: WebPageState) -> WebPageState:
        new_state = state.clone()
        soup = BeautifulSoup(new_state.current_html, "html.parser")
        for a in soup.find_all("a", href=True):
            btn = soup.new_tag("button", onclick=f"window.location.href='{a['href']}'")
            btn.string = a.string or "Link"
            a.replace_with(btn)
        new_state.current_html = str(soup)
        new_state.mutation_history.append(self.name)
        return new_state


ALL_MUTATIONS = [
    UrlAddQueryMutation(),
    UrlAddFragmentMutation(),
    HtmlAddBenignTextMutation(),
    HtmlAddDummyScriptMutation(),
    HtmlAddExternalLinkMutation(),
    HtmlObfuscateTextMutation(),
    HtmlAddCosmeticDivMutation(),
    HtmlInsertBenignMetaMutation(),
    UrlRemoveSuspiciousKeywordsMutation(),
    HtmlObfuscateFormActionMutation(),
    HtmlSwapPasswordInputMutation(),
    HtmlAddMassiveBenignTextMutation(),
    HtmlConvertLinksToButtonsMutation()
]
