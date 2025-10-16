import os, hmac, hashlib
from fastapi import FastAPI, Request, Header, HTTPException, BackgroundTasks

app = FastAPI()
SECRET = (os.getenv("GH_WEBHOOK_SECRET") or "").encode()

def verify_sig(raw: bytes, sig_hdr: str | None) -> bool:
    if not SECRET:  # allow empty secret for quick local tests
        return True
    if not sig_hdr:
        return False
    mac = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig_hdr)

def handle(event: str, payload: dict):
    if event == "ping":
        print("Ping:", payload.get("zen"))
    elif event == "push":
        print("Push:", payload.get("ref"), "commits:", len(payload.get("commits", [])))
    elif event == "pull_request":
        print("PR:", payload.get("action"), "#", payload.get("number"))
    else:
        print("Unhandled:", event)

@app.post("/webhook")
async def webhook(
    request: Request,
    bg: BackgroundTasks,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
    x_github_delivery: str = Header(None),
):
    raw = await request.body()
    if not verify_sig(raw, x_hub_signature_256):
        print("Bad signature for delivery", x_github_delivery)
        raise HTTPException(status_code=401, detail="Invalid signature")
    payload = await request.json()
    bg.add_task(handle, x_github_event or "unknown", payload)
    return {"ok": True, "delivery": x_github_delivery, "event": x_github_event}
