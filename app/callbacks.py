import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from .contracts import CallbackEvent
from .repository import StateRepository
from .secrets import read_secret_file


class CallbackDispatcher:
    def __init__(
        self,
        url: str | None,
        hmac_file: str,
        repository: StateRepository,
        ca_file: str | bool = True,
        client: httpx.AsyncClient | None = None,
    ):
        if url:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("callback URL must be credential-free HTTPS")
        self.url = url
        self.hmac_file = hmac_file
        self.repository = repository
        self.ca_file = ca_file
        self.client = client

    async def enqueue_and_dispatch(self, event: CallbackEvent) -> bool:
        self.repository.enqueue_callback(event.event_id, event.model_dump(mode="json"))
        return await self._dispatch(event.event_id, event.model_dump(mode="json"), 0)

    async def _dispatch(self, event_id: str, payload: dict, attempts: int) -> bool:
        if not self.url:
            self.repository.mark_callback(
                event_id,
                False,
                "callback_url_not_configured",
                datetime.now(UTC) + timedelta(seconds=60),
            )
            return False
        secret = read_secret_file(self.hmac_file)
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(
            secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256
        ).hexdigest()
        headers = {
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Signature": f"sha256={signature}",
            "X-Codestra-Event-ID": event_id,
            "Idempotency-Key": event_id,
            "Content-Type": "application/json",
        }
        owned = self.client is None
        client = self.client or httpx.AsyncClient(
            timeout=httpx.Timeout(10, connect=3),
            verify=self.ca_file,
            follow_redirects=False,
        )
        try:
            response = await client.post(self.url, content=raw, headers=headers)
            delivered = response.status_code in {200, 202, 204, 409}
            retry_at = (
                None
                if delivered
                else datetime.now(UTC)
                + timedelta(seconds=min(2 ** min(attempts + 1, 8), 300))
            )
            self.repository.mark_callback(
                event_id,
                delivered,
                None if delivered else f"http_{response.status_code}",
                retry_at,
            )
            return delivered
        except httpx.HTTPError:
            self.repository.mark_callback(
                event_id,
                False,
                "transport_error",
                datetime.now(UTC)
                + timedelta(seconds=min(2 ** min(attempts + 1, 8), 300)),
            )
            return False
        finally:
            if owned:
                await client.aclose()

    async def dispatch_due(self):
        for row in self.repository.due_callbacks():
            await self._dispatch(
                row["event_id"], json.loads(row["payload_json"]), row["attempt_count"]
            )
