"""Supply-chain analysis: licences, end-of-life runtimes, and name-confusion.

These engines answer questions an advisory database cannot. "Is this package
vulnerable?" has a CVE behind it; "is this package the one you meant?" and "is
this runtime still getting security patches?" do not, and they are the
questions that a dependency-confusion or an unpatched-base-image incident turns
on.

All three read files and none reach the network.
"""
