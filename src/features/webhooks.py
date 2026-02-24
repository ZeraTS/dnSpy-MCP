#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import logging
from typing import Optional, Callable

class WebhookManager:
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def send(self, url: str, event: str, payload: dict, headers: dict = None):
        headers = headers or {}
        headers["Content-Type"] = "application/json"

        body = {
            "event": event,
            "payload": payload
        }

        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=body,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as resp:
                        if resp.status >= 400:
                            self.logger.warning(
                                f"Webhook failed (attempt {attempt + 1}/{self.max_retries}): "
                                f"{resp.status}"
                            )
                            if attempt < self.max_retries - 1:
                                await asyncio.sleep(2 ** attempt)
                                continue

                        self.logger.info(f"Webhook delivered: {event}")
                        return True

            except asyncio.TimeoutError:
                self.logger.warning(
                    f"Webhook timeout (attempt {attempt + 1}/{self.max_retries})"
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except Exception as e:
                self.logger.error(f"Webhook error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

        self.logger.error(f"Webhook failed after {self.max_retries} attempts")
        return False

    async def send_async(self, url: str, event: str, payload: dict):
        try:
            await self.send(url, event, payload)
        except Exception as e:
            self.logger.error(f"Async webhook error: {e}")

class WebhookEventTypes:
    DECOMPILE_COMPLETE = "decompile.complete"
    DECOMPILE_FAILED = "decompile.failed"
    ANALYSIS_COMPLETE = "analysis.complete"
    BATCH_COMPLETE = "batch.complete"
    BATCH_PROGRESS = "batch.progress"
    WORKER_ERROR = "worker.error"
