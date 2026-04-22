"""Pytest root marker + sys.path setup.

Presence of this file makes the repo root pytest's rootdir. We
explicitly insert the repo root on sys.path so test files can
`from collector.sources.osv import ...` without a pip install.
Needed because test/collector/__init__.py promotes test/ to a
package, which shifts pytest's default import root to test/ rather
than the repo root.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
