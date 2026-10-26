"""The provider-neutral core of Glorfindel's response (A1): which actions run alone and
their errors (policy), resource ids, the local state of isolations and blocks, and the
locks that keep one writer per VM. Nothing here imports a provider's SDK; the cloud side
is in glorfindel/providers/. The import path stays glorfindel.actions (see its docstring).
"""
