"""What a verification of a binding concluded. Three values, and never a boolean.

This is the same vocabulary the disposition uses, one level up. A disposition says what is known
about a *claim*; a verdict says what is known about a *record of that claim*. Both refuse the
collapse that makes the third value necessary: a check that could not run and a check that failed
are different facts, and a consumer reading `false` cannot tell them apart.

`unverifiable` outranks `contradicted` when the two meet. An artifact that could not be read means
the binding was not fully checked, so reporting `contradicted` on the strength of the parts that
were read asserts more than was established -- and reporting `verified` asserts very much more.
The rule is the sibling attestation project's, reimplemented here rather than imported: the
projects agree on the vocabulary by argument, and a shared package would make one of them the
other's dependency for the sake of eleven lines.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Verdict"]


class Verdict(StrEnum):
    """The three conclusions a verification reaches."""

    VERIFIED = "verified"
    """Every check ran and every check held."""

    CONTRADICTED = "contradicted"
    """A check ran and did not hold. Something recorded here is no longer true."""

    UNVERIFIABLE = "unverifiable"
    """A check could not run. Nothing here is refuted; nothing here is confirmed."""

    @classmethod
    def combine(cls, verdicts: list[Verdict]) -> Verdict:
        """The weakest wins, with `unverifiable` weaker than `contradicted`.

        An empty list is `unverifiable`, not `verified`: nothing checked is not a pass, and a
        verification whose checks all vanished -- a glob matching nothing, a record holding no
        artifacts -- must not report success over an empty chain.
        """
        if not verdicts:
            return cls.UNVERIFIABLE
        if cls.UNVERIFIABLE in verdicts:
            return cls.UNVERIFIABLE
        if cls.CONTRADICTED in verdicts:
            return cls.CONTRADICTED
        return cls.VERIFIED
