from fastapi import FastAPI, Request, Header, HTTPException, BackgroundTasks
import os, hmac, hashlib, json
from collections import deque
from datetime import datetime

app = FastAPI()
SECRET = (os.getenv("GH_WEBHOOK_SECRET") or "").encode()

# keep the last few deliveries in memory so you can view them
DELIVERIES = deque(maxlen=10)

def verify_sig(raw: bytes, sig_hdr: str | None) -> bool:
    if not SECRET:  # allow empty secret for quick local tests
        return True
    if not sig_hdr:
        return False
    mac = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig_hdr)

def save_to_file(obj: dict):
    # writes each delivery to disk (handy for debugging)
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S-%f")
    os.makedirs("webhook_logs", exist_ok=True)
    with open(f"webhook_logs/delivery-{ts}.json", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

@app.get("/webhook")
async def webhook_get():
    # So hitting in a browser doesn’t 405; it won’t process anything.
    return {"ok": True, "hint": "This endpoint expects POST from GitHub/smee."}

@app.get("/deliveries")
async def deliveries():
    # View the last few payloads you received
    return list(DELIVERIES)

@app.post("/webhook")
async def webhook_post(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str | None = Header(None),
    x_hub_signature_256: str | None = Header(None),
    x_github_delivery: str | None = Header(None),
):
    raw = await request.body()

    # If you want to temporarily bypass signature while testing, set no GH_WEBHOOK_SECRET
    if not verify_sig(raw, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    record = {
        "received_at": datetime.utcnow().isoformat() + "Z",
        "delivery_id": x_github_delivery,
        "event": x_github_event,
        "headers": {
            "X-GitHub-Event": x_github_event,
            "X-Hub-Signature-256": x_hub_signature_256,
            "X-GitHub-Delivery": x_github_delivery,
        },
        "body": payload,
    }
    DELIVERIES.appendleft(record)
    background.add_task(save_to_file, record)

    # ACK fast; view JSON later at GET /deliveries or in webhook_logs/
    return {"ok": True, "delivery": x_github_delivery, "event": x_github_event}
