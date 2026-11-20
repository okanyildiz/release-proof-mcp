from release_proof_mcp import __version__
from release_proof_mcp.mcp import MCPServer, PROTOCOL_VERSION, TOOL_DEFINITION


def test_server_info_version_matches_package_version() -> None:
    response = MCPServer().handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "version-test", "version": "1.0.0"},
            },
        }
    )

    assert response["result"]["serverInfo"]["version"] == __version__
    for guidance in (response["result"]["instructions"], TOOL_DEFINITION["description"]):
        assert "receipt document itself is not a cryptographic signature" in guidance
        assert "`proof` exists only when DSSE signing is explicitly configured" in guidance
        assert (
            "absence of `proof` means unsigned regardless of schema_version, receipt_id, or status"
            in guidance
        )
        assert "Never infer proof from failed/verified status alone" in guidance
