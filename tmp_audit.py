import os, io
os.environ["SQLITE_FALLBACK"] = "sqlite:////tmp/audit.db"
os.environ["USE_SQLITE_FALLBACK"] = "true"
if os.path.exists("/tmp/audit.db"):
    os.remove("/tmp/audit.db")

from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.bloc5_dashboard.api import inference
from src.common.config import settings

PH = "URGENT confirmez votre code PIN MoMo http://bit.ly/x sinon compte suspendu"

def make_client():
    app = FastAPI()
    app.include_router(inference.router)
    return TestClient(app)

c = make_client()

# 1. txt normal -> OK
r = c.post("/api/upload", files={"file": ("ok.txt", io.BytesIO((PH+"\n").encode()), "text/plain")})
print("txt_ok", r.status_code)

# 2. trop volumineux > 2Mo -> 413
big = (b"a\n" * (2*1024*1024))  # ~4Mo
r = c.post("/api/upload", files={"file": ("big.txt", io.BytesIO(big), "text/plain")})
print("too_big", r.status_code, r.json().get("detail","")[:40])

# 3. trop de lignes > 5000 mais < 2Mo -> 400
many = ("x\n" * 6000).encode()  # 12000 bytes, 6000 lines
print("many_bytes", len(many))
r = c.post("/api/upload", files={"file": ("many.txt", io.BytesIO(many), "text/plain")})
print("too_many_rows", r.status_code, r.json().get("detail","")[:40])

# 4. fichier vide -> 400
r = c.post("/api/upload", files={"file": ("e.txt", io.BytesIO(b""), "text/plain")})
print("empty", r.status_code)

# 5. mauvaise extension -> 400
r = c.post("/api/upload", files={"file": ("x.json", io.BytesIO(b"{}"), "application/json")})
print("bad_ext", r.status_code)

# 6. AUTH: pas de cle -> upload autorise (dev permissif)
print("api_key_default", repr(settings.api_key))
r = c.post("/api/upload", files={"file": ("ok.txt", io.BytesIO((PH+"\n").encode()), "text/plain")})
print("no_key_when_empty", r.status_code)

# 7. AUTH: cle definie -> upload SANS cle refuse 401, AVEC bonne cle OK
settings.api_key = "secret123"
c2 = make_client()
r = c2.post("/api/upload", files={"file": ("ok.txt", io.BytesIO((PH+"\n").encode()), "text/plain")})
print("no_key_when_set", r.status_code)
r = c2.post("/api/upload", headers={"X-API-Key":"wrong"}, files={"file": ("ok.txt", io.BytesIO((PH+"\n").encode()), "text/plain")})
print("wrong_key", r.status_code)
r = c2.post("/api/upload", headers={"X-API-Key":"secret123"}, files={"file": ("ok.txt", io.BytesIO((PH+"\n").encode()), "text/plain")})
print("good_key", r.status_code)
settings.api_key = ""

# 8. app import + route count
from src.bloc5_dashboard.api.main import app
print("app_OK", len(app.routes))
print("DONE")
