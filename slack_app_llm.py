import hashlib
import hmac
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from langchain_openai import ChatOpenAI
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

load_dotenv()
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]

client = WebClient(token=SLACK_BOT_TOKEN)
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
app = FastAPI(title="Slack LLM Bot")
_seen: set[str] = set()


def verify_slack_signature(body: bytes, timestamp: str | None, signature: str | None) -> None:
    if not timestamp or not signature:
        raise HTTPException(status_code=401, detail="missing signature headers")
    if abs(time.time() - int(timestamp)) > 60 * 5:
        raise HTTPException(status_code=401, detail="stale request")
    base = f"v0:{timestamp}:{body.decode('utf-8')}"
    digest = hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        base.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(f"v0={digest}", signature):
        raise HTTPException(status_code=401, detail="invalid signature")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/slack/events")
async def slack_events(
    request: Request,
    x_slack_signature: str | None = Header(default=None),
    x_slack_request_timestamp: str | None = Header(default=None),
):
    body = await request.body()
    verify_slack_signature(body, x_slack_request_timestamp, x_slack_signature)
    payload = await request.json()

    if payload.get("type") == "url_verification":
        return {"challenge": payload.get("challenge")}

    if payload.get("type") != "event_callback":
        return {"ok": True}

    event_id = payload.get("event_id")
    if event_id:
        if event_id in _seen:
            return {"ok": True}
        _seen.add(event_id)

    event = payload.get("event") or {}
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return {"ok": True}

    text = (event.get("text") or "").strip()
    channel = event.get("channel")
    if not text or not channel:
        return {"ok": True}

    if event.get("type") == "app_mention":
        parts = text.split(maxsplit=1)
        text = parts[1] if len(parts) > 1 else text

    print("받은 메시지:", text)
    try:
        answer = llm.invoke(text).content
        client.chat_postMessage(channel=channel, text=answer)
    except SlackApiError as e:
        print("postMessage 실패:", e.response.get("error"))
    except Exception as e:
        print("LLM 실패:", e)
        try:
            client.chat_postMessage(channel=channel, text="답변 생성 중 오류가 발생했습니다.")
        except SlackApiError:
            pass

    return {"ok": True}