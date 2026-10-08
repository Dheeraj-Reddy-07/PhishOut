from bs4 import BeautifulSoup
from .webpage_state import WebPageState

def is_valid_candidate(state: WebPageState) -> bool:
    """
    Checks if the mutated HTML is valid and doesn't break basic structures.
    """
    if not state.current_html or not state.current_url:
        return False
        
    try:
        soup = BeautifulSoup(state.current_html, "html.parser")
        orig_soup = BeautifulSoup(state.original_html, "html.parser")
        
        # Constraint 1: If original had a body, candidate should have a body
        if orig_soup.body and not soup.body:
            return False
            
        # Constraint 2: The length shouldn't be completely decimated
        if len(state.current_html) < len(state.original_html) * 0.1:
            return False
            
        return True
    except Exception:
        return False
