"""PROVENANCE MCP stdio interface."""

from .server import (
    MCP_INTERFACE_ID,
    MCP_SERVER_INFO,
    ProvenanceMCPServer,
    serve_stdio,
)

__all__ = [
    "MCP_INTERFACE_ID",
    "MCP_SERVER_INFO",
    "ProvenanceMCPServer",
    "serve_stdio",
]
