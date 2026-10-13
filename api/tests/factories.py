"""Filas de prueba para los tests de la api."""

from datetime import datetime, timezone

from app.models import ScanRequest

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def _request(job_id, seq, **overrides) -> ScanRequest:
    values = dict(
        job_id=job_id,
        seq=seq,
        ts=NOW,
        method="GET",
        url=f"http://site.example/r{seq}?a=1&a=2",
        url_truncated=False,
        scheme="http",
        host="site.example",
        path=f"/r{seq}",
        query_params=[["a", "1"], ["a", "2"]],
        resource_type="image",
        frame_url="http://site.example/",
        is_navigation=False,
        initiator=None,
        request_headers=[{"name": "accept", "value": "*/*"}],
        response_status=200,
        response_headers=[{"name": "content-type", "value": "image/png"}],
        mime_type="image/png",
        blocked_by_proxy=False,
        third_party=False,
        registrable_domain="site.example",
    )
    values.update(overrides)
    return ScanRequest(**values)
