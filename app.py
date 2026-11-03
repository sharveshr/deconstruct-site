"""Deconstruct Site: paste a URL, get a full breakdown of how the site is built."""
from flask import Flask, jsonify, request, send_from_directory

from analyzer import AnalysisError, analyze

app = Flask(__name__, static_folder="static")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/analyze")
def api_analyze():
    body = request.get_json(silent=True) or {}
    url = body.get("url", "").strip()
    if not url:
        return jsonify(ok=False, error="Enter a URL."), 400
    try:
        return jsonify(ok=True, data=analyze(url, render=body.get("render", True) is not False))
    except AnalysisError as e:
        return jsonify(ok=False, error=str(e)), 422


@app.get("/api/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5173, debug=False, threaded=True)
