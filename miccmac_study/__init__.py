"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Study instruments for the automated-vs-blind-manual MICCMAC comparison.

These tools are not part of the miccmac assessment tool under test. They
generate the blank manual worksheets, keep a SHA-256 ledger of study files
(with an archive copy of each), keep the tool's results sealed until every
manual worksheet is hashed, check sealed tool outputs without revealing
results, build the risk-register review sheets after the manual passes, and
compute the agreement statistics named in the study protocol (sections 6-9).
The researcher's guide is miccmac_study/README.md.

Run them from the repository root, or from any folder with PYTHONPATH set
to the repository root (they are not installed with the package):

    python -m miccmac_study --help

Drafted with AI assistance (Claude Code, Anthropic) for the researcher to
review and test. That assistance is declared in miccmac_study/README.md and
in the first docstring line of every module and test file of the
instruments. Every judgment in the study (manual verdicts and levels,
register ratings, root causes, interpretation) is entered by the researcher;
nothing here fills those fields.
"""
from __future__ import annotations

__version__ = "0.1.0"
