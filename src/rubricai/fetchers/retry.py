"""Shared HTTP retry helper for all fetchers.

Implements exponential backoff (1s → 2s → 4s) with max 3 retries on transient
failures: 429 (rate limit), 5xx server errors, and network-level exceptions.

Note: fcntl-based file locking elsewhere in this project is Linux/macOS only.
"""

import asyncio
import logging

import httpx

_logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds — doubles each retry (1, 2, 4)


async def fetch_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int = _MAX_RETRIES,
    **kwargs,
) -> httpx.Response:
    """Execute an HTTP request with exponential backoff on transient failures.

    Retries on: 429 (rate limit), 503 (service unavailable), 5xx server errors,
    and network-level httpx errors. Non-retryable errors (4xx except 429) are
    returned immediately for the caller to handle (e.g. 404).

    Args:
        client: An httpx.AsyncClient instance.
        method: HTTP method ("GET" or "POST").
        url: Request URL.
        max_retries: Maximum number of retry attempts (default: 3).
        **kwargs: Passed through to client.request().

    Returns:
        The httpx.Response on success or final attempt.

    Raises:
        httpx.HTTPError: After all retries exhausted on network errors.
    """
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)

            # Non-retryable client errors (except 429)
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                return resp

            # Retryable server errors
            if resp.status_code in (429, 500, 502, 503, 504):
                if attempt < max_retries:
                    wait = _BACKOFF_BASE * (2**attempt)
                    _logger.warning(
                        "HTTP %d from %s — retry %d/%d in %.1fs",
                        resp.status_code,
                        url,
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                # Final attempt — return the error response for caller to handle
                return resp

            return resp

        except httpx.HTTPError as exc:
            last_exc = exc
            if attempt < max_retries:
                wait = _BACKOFF_BASE * (2**attempt)
                _logger.warning(
                    "%s fetching %s — retry %d/%d in %.1fs",
                    type(exc).__name__,
                    url,
                    attempt + 1,
                    max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
            else:
                raise

    # Should not reach here, but satisfy type checker
    if last_exc:
        raise last_exc
    raise httpx.HTTPError("Retry exhausted")  # pragma: no cover
