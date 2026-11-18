from .mcp import MCPServer


def main() -> None:
    MCPServer().serve()
