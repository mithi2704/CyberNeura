"""
API and Agent Tool tests for CyberNeura AI Media Security Subsystem (Phase 7).
"""
import io
import asyncio
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.agent.tools.media_tools import (
    AnalyzeImageTool,
    AnalyzeVideoTool,
    MediaEvidenceTool,
    MediaProvenanceTool,
    MediaForensicsTool,
    FrameAnalysisTool,
)
from app.agent.tool_result import ToolStatus
from app.services.scan_store import scan_store


@pytest.fixture
def client():
    return TestClient(app)


def test_media_stats_endpoint(client):
    res = client.get("/api/v1/media/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_analyzed" in data
    assert "average_confidence" in data


def test_image_analysis_endpoint(client):
    # Generate test image in memory
    buf = io.BytesIO()
    img = Image.new("RGB", (120, 120), color=(100, 150, 200))
    img.save(buf, format="PNG")
    buf.seek(0)

    files = {"file": ("test_sample.png", buf, "image/png")}
    res = client.post("/api/v1/media/images/analyze", files=files)
    assert res.status_code == 200
    data = res.json()

    assert "media_id" in data
    assert data["classification"] in ("LIKELY_AUTHENTIC", "SUSPICIOUS", "LIKELY_AI_GENERATED", "INCONCLUSIVE")
    assert 0.0 <= data["risk_score"] <= 100.0
    assert 0.0 <= data["confidence"] <= 100.0
    assert "summary" in data

    # Verify asset was indexed in scan_store
    media_id = data["media_id"]
    assessment = scan_store.get_media_assessment(media_id)
    assert assessment is not None

    # Test individual detail endpoints
    ev_res = client.get(f"/api/v1/media/{media_id}/evidence")
    assert ev_res.status_code == 200

    prov_res = client.get(f"/api/v1/media/{media_id}/provenance")
    assert prov_res.status_code == 200

    foren_res = client.get(f"/api/v1/media/{media_id}/forensics")
    assert foren_res.status_code == 200


def test_agent_media_tools():
    async def _run():
        # Test AnalyzeImageTool
        tool = AnalyzeImageTool()
        res = await tool.execute({})
        assert res.status == ToolStatus.ERROR

        # Test MediaEvidenceTool with missing media
        ev_tool = MediaEvidenceTool()
        res2 = await ev_tool.execute({"media_id": "non-existent-media-id"})
        assert res2.status == ToolStatus.NO_DATA

    asyncio.run(_run())
