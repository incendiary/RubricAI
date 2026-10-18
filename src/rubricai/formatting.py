"""Small display helpers shared by policy rationales and report templates."""


def fmt_epss(score: float, digits: int = 3) -> str:
    """Format an EPSS score, never showing 1.000 for a score below 1.

    A score of 0.99999 rounds to 1.000 at three decimals, which reads as certainty.
    In that case show the exact value instead.
    """
    text = f"{score:.{digits}f}"
    if float(text) == 1 and score < 1:
        return f"{score:.7f}".rstrip("0")
    return text
