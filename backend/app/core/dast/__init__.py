"""Dynamic application security testing: crawl a web application, then test it.

`crawl.py` is the part that matters. See its module docstring for why a
discovered URL is checked *before* it enters the queue rather than before it is
fetched.
"""
