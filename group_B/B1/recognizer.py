"""Shim so the recogniser can be imported under the allowlisted name.

    from group_B.B1.recognizer import recognise        # as a package
    from recognizer import recognise                    # with group_B/B1 on sys.path

It only re-exports recognise.py; there is no logic here.
"""
try:
    from .recognise import PIPELINES, TEMPLATES, recognise
except ImportError:  # imported as a top-level module, not as part of a package
    from recognise import PIPELINES, TEMPLATES, recognise

__all__ = ["recognise", "PIPELINES", "TEMPLATES"]
