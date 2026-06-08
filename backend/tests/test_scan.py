import pytest


@pytest.mark.asyncio
async def test_scan_url(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    login_res = await client.post("/api/v1/auth/login", json=sample_user)
    token = login_res.json()["access_token"]

    response = await client.post(
        "/api/v1/scan",
        json={"url": "https://example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert "risk_score" in data
    assert "threat_level" in data
    assert "signals" in data
    assert 0 <= data["risk_score"] <= 100


@pytest.mark.asyncio
async def test_scan_url_unauthorized(client):
    response = await client.post(
        "/api/v1/scan", json={"url": "https://example.com"}
    )
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_scan_invalid_url(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    login_res = await client.post("/api/v1/auth/login", json=sample_user)
    token = login_res.json()["access_token"]

    response = await client.post(
        "/api/v1/scan",
        json={"url": ""},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_scan_history(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    login_res = await client.post("/api/v1/auth/login", json=sample_user)
    token = login_res.json()["access_token"]

    await client.post(
        "/api/v1/scan",
        json={"url": "https://example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )

    response = await client.get(
        "/api/v1/scan/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
