"""Shared HTTP retry helper for all fetchers.

Implements exponential backoff (1s → 2s → 4s) with max 3 retries on transient
failures: 429 (rate limit), 5xx server errors, and network-level exceptions.

Also implements timeout escalation: on timeout errors, automatically retries with
increasing timeout windows (5s → 10s → 30s) to handle slow/congested networks.

Note: fcntl-based file locking elsewhere in this project is Linux/macOS only.
"""

import asyncio
import logging
import os

import httpx

_logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds — doubles each retry (1, 2, 4)
_RETRYABLE = (429, 500, 502, 503, 504)


def _timeout_windows() -> tuple[int, ...]:
    """Escalating windows (5s, 10s, cap); cap is RUBRICAI_HTTP_TIMEOUT, default 30."""
    try:
        cap = int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))
    except ValueError:
        cap = 30
    if cap <= 0:
        cap = 30
    return (5, 10, min(30, cap))


async def fetch_with_timeout_escalation(
    method: str,
    url: str,
    *,
    timeout_windows: tuple[int, ...] | None = None,
    max_retries: int = _MAX_RETRIES,
    **kwargs,
) -> httpx.Response:
    """Execute an HTTP request with exponential backoff and timeout escalation.

    Tries the request with increasing timeout windows (default: 5s → 10s → 30s,
    the last capped by RUBRICAI_HTTP_TIMEOUT).
    If a timeout occurs, escalates to the next window and retries.
    Within each window, 429/5xx/network errors use exponential backoff;
    timeouts are not retried in-window. Other 4xx responses (e.g. 404) are
    returned immediately for the caller to handle.

    This is useful for APIs that may be slow or behind congested networks; it
    avoids a quick failure on constrained timeouts while still failing fast if
    the server is truly unreachable.

    Args:
        method: HTTP method ("GET" or "POST").
        url: Request URL.
        timeout_windows: Tuple of timeout values to try in sequence (seconds).
        max_retries: Maximum exponential-backoff retries per timeout window.
        **kwargs: Passed through to client.request() (headers, params, etc.).

    Returns:
        The httpx.Response on success or final attempt.

    Raises:
        httpx.HTTPError: After all timeout windows and retries exhausted.
    """
    timeout_windows = timeout_windows or _timeout_windows()

    for timeout_attempt, timeout_sec in enumerate(timeout_windows):
        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                for attempt in range(max_retries + 1):
                    wait = _BACKOFF_BASE * (2**attempt)
                    try:
                        resp = await client.request(method, url, **kwargs)
                    except httpx.HTTPError as exc:
                        # Escalation to a longer window is the retry for timeouts
                        if isinstance(exc, httpx.TimeoutException) or (
                            attempt == max_retries
                        ):
                            raise
                        _logger.warning(
                            "%s fetching %s — retry %d/%d in %.1fs",
                            type(exc).__name__,
                            url,
                            attempt + 1,
                            max_retries,
                            wait,
                        )
                    else:
                        if resp.status_code not in _RETRYABLE or attempt == max_retries:
                            break
                        _logger.warning(
                            "HTTP %d from %s — retry %d/%d in %.1fs",
                            resp.status_code,
                            url,
                            attempt + 1,
                            max_retries,
                            wait,
                        )
                    await asyncio.sleep(wait)
                if timeout_attempt > 0:
                    _logger.info(
                        "Request to %s succeeded with timeout=%ds (window %d/%d)",
                        url,
                        timeout_sec,
                        timeout_attempt + 1,
                        len(timeout_windows),
                    )
                return resp

        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            if timeout_attempt < len(timeout_windows) - 1:
                next_timeout = timeout_windows[timeout_attempt + 1]
                _logger.warning(
                    "%s on %s with timeout=%ds — escalating to %ds (window %d/%d)",
                    type(exc).__name__,
                    url,
                    timeout_sec,
                    next_timeout,
                    timeout_attempt + 1,
                    len(timeout_windows),
                )
            else:
                _logger.error(
                    "%s on %s exhausted all timeout windows %s — giving up",
                    type(exc).__name__,
                    url,
                    timeout_windows,
                )
                raise
