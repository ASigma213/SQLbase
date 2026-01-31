"""
Vulnerability predictor: heuristic-based (ML-ready). Cross-platform.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import re


class VulnerabilityPredictor:
    def __init__(self) -> None:
        self.model = self.load_trained_model()
        self.features = [
            "code_complexity",
            "input_sources_count",
            "database_interactions",
            "authentication_points",
        ]

    def load_trained_model(self) -> Optional[Any]:
        try:
            from sklearn.ensemble import RandomForestClassifier
            import numpy as np
            # Placeholder: no real training data; use simple heuristic weights
            clf = RandomForestClassifier(n_estimators=10, random_state=42)
            # Dummy fit so predict doesn't fail; real usage would load a serialized model
            X = np.zeros((5, 4))
            y = np.array([0, 0, 1, 0, 1])
            clf.fit(X, y)
            return clf
        except ImportError:
            return None

    def extract_features(self, codebase: str | Path) -> List[float]:
        path = Path(codebase)
        text = ""
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                pass
        elif path.is_dir():
            for ext in [".py", ".java", ".js", ".ts", ".php"]:
                for f in path.rglob(f"*{ext}"):
                    try:
                        text += f.read_text(encoding="utf-8", errors="replace") + "\n"
                    except (OSError, PermissionError):
                        continue
        else:
            text = str(codebase)

        # Heuristic features
        code_complexity = min(1.0, (len(text) / 10000) + (text.count("\n") / 500) * 0.1)
        input_sources = len(re.findall(r"(input|request\.(get|post)|argv|getParameter)", text, re.I))
        input_sources_count = min(1.0, input_sources / 20)
        db_interactions = len(
            re.findall(
                r"(execute|query|raw|prepareStatement|SELECT|INSERT|UPDATE|DELETE)",
                text,
                re.I,
            )
        )
        database_interactions = min(1.0, db_interactions / 30)
        auth_points = len(
            re.findall(r"(password|login|auth|session|token|credential)", text, re.I)
        )
        authentication_points = min(1.0, auth_points / 15)

        return [
            code_complexity,
            input_sources_count,
            database_interactions,
            authentication_points,
        ]

    def generate_recommendations(self, predictions: Dict[str, float]) -> List[str]:
        recs: List[str] = []
        if predictions.get("sqli", 0) > 0.5:
            recs.append("Use parameterized queries / PreparedStatement for all DB access.")
        if predictions.get("xss", 0) > 0.5:
            recs.append("Escape user-controlled output; consider CSP and encoding libraries.")
        if not recs:
            recs.append("Review input validation and output encoding.")
        return recs

    def predict_vulnerability_likelihood(
        self, codebase: str | Path
    ) -> Dict[str, Any]:
        features = self.extract_features(codebase)
        predictions = {"sqli": 0.0, "xss": 0.0}
        if self.model is not None:
            try:
                import numpy as np
                X = np.array([features])
                pred = self.model.predict_proba(X)
                if pred.shape[1] >= 2:
                    predictions["sqli"] = float(pred[0][1])
                    predictions["xss"] = float(pred[0][1]) * 0.8
                else:
                    predictions["sqli"] = 0.3 * (features[1] + features[2])
                    predictions["xss"] = 0.3 * (features[1] + features[3])
            except Exception:
                predictions["sqli"] = 0.3 * (features[1] + features[2])
                predictions["xss"] = 0.3 * (features[1] + features[3])
        else:
            predictions["sqli"] = 0.3 * (features[1] + features[2])
            predictions["xss"] = 0.3 * (features[1] + features[3])

        return {
            "sql_injection_risk": round(predictions["sqli"], 4),
            "xss_risk": round(predictions["xss"], 4),
            "recommended_fixes": self.generate_recommendations(predictions),
            "features": dict(zip(self.features, features)),
        }
