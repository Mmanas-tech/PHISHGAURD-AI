import pytest


@pytest.mark.asyncio
async def test_register_user(client, sample_user):
    response = await client.post("/api/v1/auth/register", json=sample_user)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == sample_user["email"]
    assert "id" in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    response = await client.post("/api/v1/auth/register", json=sample_user)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    response = await client.post("/api/v1/auth/login", json=sample_user)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_credentials(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": sample_user["email"], "password": "wrongpassword"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    login_res = await client.post("/api/v1/auth/login", json=sample_user)
    refresh_token = login_res.json()["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_get_me(client, sample_user):
    await client.post("/api/v1/auth/register", json=sample_user)
    login_res = await client.post("/api/v1/auth/login", json=sample_user)
    token = login_res.json()["access_token"]

    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == sample_user["email"]


@pytest.mark.asyncio
async def test_get_me_unauthorized(client):
    response = await client.get("/api/v1/auth/me")
    assert response.status_code in [401, 403]
