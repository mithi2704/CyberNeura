"""
Tool 1: ML Analysis Tool (`analyze_ml_prediction`).
Wraps the existing production LightGBM ML model.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.feature_extractor import extract_features
from app.ml.predictor import predict, get_model_metadata
from app.services.scan_store import scan_store


class MLAnalysisInput(BaseModel):
    url: Optional[str] = Field(None, description="The URL to analyze with the ML model")
    scan_id: Optional[str] = Field(None, description="Optional scan ID to retrieve existing ML prediction")


class MLAnalysisTool(AgentTool):
    tool_name = "analyze_ml_prediction"
    description = "Run or retrieve ML model inference on a URL to get phishing probability and confidence."
    input_schema = MLAnalysisInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        url = arguments.get("url")
        scan_id = arguments.get("scan_id")

        if not url and scan_id:
            scan = scan_store.get_scan(scan_id)
            if scan:
                url = scan.get("url")

        if not url:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A valid URL or scan_id must be provided for ML analysis.",
                error="MISSING_URL",
            )

        try:
            features = extract_features(url)
            prediction, prob, confidence, feature_imp = predict(features)

            meta = get_model_metadata()
            model_ver = meta.get("version", "1.0.0")

            top_indicators = sorted(feature_imp.items(), key=lambda x: x[1], reverse=True)[:5]

            data = {
                "url": url,
                "prediction": prediction.upper(),
                "probability": round(prob, 4),
                "confidence": round(confidence, 2),
                "model_version": model_ver,
                "features_analyzed": len(features),
                "top_indicators": [f"{k}: {v}" for k, v in top_indicators],
            }

            summary = (
                f"ML model evaluated URL as {prediction.upper()} with {prob:.1%} phishing probability "
                f"({confidence:.1f}% confidence)."
            )

            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.SUCCESS,
                data=data,
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"ML prediction failed: {exc}",
                error=str(exc),
            )
