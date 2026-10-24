"""EXPERIMENT-ONLY (W7): seeded stand-in for the run-to-run variation an unconstrained LLM planner produces.
It is NOT an LLM and its results must never be reported as LLM behaviour. It lets us measure which engine controls
absorb which kind of variation (step order, omitted steps, result-size choices)."""
from __future__ import annotations
import copy, random
from .models import HuntPlan


def perturb_plan(plan: HuntPlan, seed: int, p_drop: float = 0.4) -> HuntPlan:
    rnd = random.Random(seed)
    p = copy.deepcopy(plan)
    steps = [s for s in p.steps if s.must_have or rnd.random() > p_drop]      # omit some optional steps
    for s in steps:
        if s.tool == "search":
            s.params["size"] = rnd.choice([1, 2, 5, 25, 100])                      # arbitrary result-size choice
    rnd.shuffle(steps)                                                           # arbitrary order
    p.steps = steps
    return p
