import io

from fastapi.testclient import TestClient
from PIL import Image

from homesentry.store import Store
from homesentry.web.app import create_app


class FakeLLM:
    def __init__(self):
        self.calls = []

    def chat_json(self, messages):
        self.calls.append(messages)
        return {
            "message": "Looks like a TerraMaster F2-210.",
            "identity": {
                "device_type": "nas",
                "make": "TerraMaster",
                "model": "F2-210",
                "firmware": None,
            },
            "confidence": 0.75,
            "next": {"kind": "photo", "ask": "Settings > About screen"},
        }


def jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (40, 30), "white").save(buf, "JPEG")
    return buf.getvalue()


def test_end_to_end_manual_device_wizard_confirm(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    llm = FakeLLM()
    c = TestClient(create_app(Store(tmp_path / "t.db"), llm))
    assert c.get("/").status_code == 200

    r = c.post("/devices/new", data={"label": "Closet NAS"}, follow_redirects=False)
    url = r.headers["location"]
    assert c.get(url).status_code == 200

    r = c.post(
        url + "/wizard",
        data={"text": "the NAS in the closet"},
        files={"photos": ("label.jpg", jpeg(), "image/jpeg")},
        follow_redirects=True,
    )
    assert r.status_code == 200 and "TerraMaster F2-210" in r.text
    assert llm.calls[0][-1]["images"]  # photo went to the model
    assert "/photo/" in r.text

    r = c.post(
        url + "/confirm",
        data={
            "make": "TerraMaster",
            "model": "F2-210",
            "device_type": "nas",
            "label": "Closet NAS",
        },
        follow_redirects=True,
    )
    assert "confirmed" in r.text
    assert (tmp_path / "kb" / "terramaster-f2-210.yaml").exists()


def test_photo_route_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    c = TestClient(create_app(Store(tmp_path / "t.db"), FakeLLM()))
    assert c.get("/photo/1/..%2F..%2Ft.db").status_code == 404
