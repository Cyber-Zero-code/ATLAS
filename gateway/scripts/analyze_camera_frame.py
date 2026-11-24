#!/usr/bin/env python3
"""
Project ATLAS — Optional Vision & Biometric Sidecar Worker (Option B Companion)

Runs as an external HTTP service pointed to by `CAMERA_ANALYTICS_URL`
(e.g., http://127.0.0.1:8450/analyze) on a host where `requirements-vision.txt`
dependencies (`opencv-python-headless`, `numpy`, `insightface`, `onnxruntime`,
`ultralytics`) are installed.

Contract:
POST /analyze JSON { frameBase64, enrolledIdentities: [{ id, personLabel, embedding }] }
-> JSON { faces: [...], persons: [...] }
"""

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import cv2
import numpy as np
from insightface.app import FaceAnalysis
from ultralytics import YOLO

YOLO_MODEL = YOLO(os.environ.get("ATLAS_YOLO_MODEL", "yolov8n.pt"))
FACE_APP = FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"])
FACE_APP.prepare(ctx_id=-1, det_size=(640, 640))


def analyze_frame_bytes(frame_bytes: bytes) -> dict:
    arr = np.frombuffer(frame_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return {"faces": [], "persons": []}

    faces_out = []
    for f in FACE_APP.get(img):
        x1, y1, x2, y2 = [float(v) for v in f.bbox]
        faces_out.append(
            {
                "confidence": float(f.det_score),
                "box": {"x": x1, "y": y1, "w": x2 - x1, "h": y2 - y1},
                "embedding": [float(v) for v in f.normed_embedding.tolist()],
            }
        )

    persons_out = []
    results = YOLO_MODEL.track(img, classes=[0], persist=True, verbose=False)
    for r in results:
        if r.boxes is None:
            continue
        for b in r.boxes:
            x1, y1, x2, y2 = [float(v) for v in b.xyxy[0].tolist()]
            tid = int(b.id[0].item()) if b.id is not None else 0
            persons_out.append(
                {
                    "trackId": f"track-{tid}",
                    "confidence": float(b.conf[0].item()),
                    "box": {"x": x1, "y": y1, "w": x2 - x1, "h": y2 - y1},
                }
            )

    return {"faces": faces_out, "persons": persons_out}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        frame_bytes = base64.b64decode(body["frameBase64"])
        result = analyze_frame_bytes(frame_bytes)
        payload = json.dumps(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    host = os.environ.get("VISION_HOST", "127.0.0.1")
    port = int(os.environ.get("VISION_PORT", "8450"))
    HTTPServer((host, port), Handler).serve_forever()
