"""Providers (MC0): the interface Glorfindel asks a cloud for, and one adapter per cloud.

Azure is the only adapter (glorfindel/providers/azure/).
"""
from glorfindel.providers.interface import CloudConnector

__all__ = ["CloudConnector"]
