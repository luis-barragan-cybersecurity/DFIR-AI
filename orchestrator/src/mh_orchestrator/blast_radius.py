"""BlastRadius scoring for reversibility-gate routing.

Used by the `contain` LangGraph node to score per-recommendation impact and
by `route_after_contain` to escalate high-blast-radius actions to human_in_loop.
Default threshold 50; override via MH_BLAST_RADIUS_THRESHOLD env var.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_THRESHOLD = 50


@dataclass
class BlastRadius:
    hosts_affected: int = 0
    users_affected: int = 0
    services_affected: int = 0

    def score(self) -> int:
        """Linear score: hosts*5 + users*1 + services*3.

        Hosts dominate (5×) because rebuilding a host is the most expensive
        containment outcome; services are intermediate (3×); users are cheapest
        (1×) since user account isolation is reversible by re-enable.
        """
        return self.hosts_affected * 5 + self.users_affected * 1 + self.services_affected * 3

    def exceeds_threshold(self, threshold: int | None = None) -> bool:
        """Return True iff score() > threshold (default from env or 50)."""
        if threshold is None:
            env = os.environ.get("MH_BLAST_RADIUS_THRESHOLD")
            threshold = int(env) if env else DEFAULT_THRESHOLD
        return self.score() > threshold
