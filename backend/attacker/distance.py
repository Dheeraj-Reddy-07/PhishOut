from .webpage_state import WebPageState

def calculate_distance(orig: WebPageState, new: WebPageState) -> dict:
    """
    Calculates basic distance metrics between original and mutated state.
    """
    return {
        "mutations_applied": len(new.mutation_history),
        "url_changed": orig.current_url != new.current_url,
        "html_length_diff": len(new.current_html) - len(orig.original_html)
    }
