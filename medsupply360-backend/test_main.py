import pytest
from httpx import AsyncClient
from main import app, database
from datetime import date, timedelta

@pytest.fixture(autouse=True, scope="session")
async def connect_db():
    await database.connect()
    yield
    await database.disconnect()

@pytest.mark.asyncio
async def test_user_creation_and_login():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        # Create user
        import uuid
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        resp = await client.post("/users/", json={"username": username, "password": "strongpass123"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "testuser123"
        user_id = data["id"]

        # Try duplicate user creation
        resp2 = await client.post("/users/", json={"username": "testuser123", "password": "strongpass123"})
        assert resp2.status_code == 400

        # Login with correct credentials
        resp = await client.post("/token", data={"username": "testuser123", "password": "strongpass123"})
        assert resp.status_code == 200
        token_data = resp.json()
        assert "access_token" in token_data

        # Login with wrong password
        resp = await client.post("/token", data={"username": "testuser123", "password": "wrongpass"})
        assert resp.status_code == 401

@pytest.mark.asyncio
async def test_medicine_crud_and_auth():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        # Create user and get token
        await client.post("/users/", json={"username": "meduser", "password": "medpass123"})
        login_resp = await client.post("/token", data={"username": "meduser", "password": "medpass123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Add medicine
        med_data = {
            "name": "Aspirin",
            "batch_number": "BATCH123",
            "expiry_date": (date.today() + timedelta(days=365)).isoformat(),
            "price": 5.99,
            "quantity_in_stock": 50
        }
        resp = await client.post("/medicines/", json=med_data, headers=headers)
        assert resp.status_code == 200
        med = resp.json()
        assert med["name"] == "Aspirin"
        med_id = med["id"]

        # List medicines
        resp = await client.get("/medicines/", headers=headers)
        assert resp.status_code == 200
        meds = resp.json()
        assert any(m["id"] == med_id for m in meds)

        # Get medicine by ID
        resp = await client.get(f"/medicines/{med_id}", headers=headers)
        assert resp.status_code == 200
        med_single = resp.json()
        assert med_single["id"] == med_id

        # Update medicine (price and quantity)
        update_data = {"price": 6.49, "quantity_in_stock": 40}
        resp = await client.patch(f"/medicines/{med_id}", json=update_data, headers=headers)
        assert resp.status_code == 200
        updated_med = resp.json()
        assert updated_med["price"] == 6.49
        assert updated_med["quantity_in_stock"] == 40

        # Try unauthorized access (no token)
        resp = await client.get("/medicines/")
        assert resp.status_code == 401

@pytest.mark.asyncio
async def test_sales_record_and_stock_decrement():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        # Setup user & medicine
        await client.post("/users/", json={"username": "salesuser", "password": "salespass123"})
        login_resp = await client.post("/token", data={"username": "salesuser", "password": "salespass123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        med_data = {
            "name": "Ibuprofen",
            "batch_number": "BATCH789",
            "expiry_date": (date.today() + timedelta(days=365)).isoformat(),
            "price": 8.99,
            "quantity_in_stock": 30
        }
        resp = await client.post("/medicines/", json=med_data, headers=headers)
        med_id = resp.json()["id"]

        # Record sale with enough stock
        sale_data = {"medicine_id": med_id, "quantity_sold": 10}
        resp = await client.post("/sales/", json=sale_data, headers=headers)
        assert resp.status_code == 200
        sale = resp.json()
        assert sale["quantity_sold"] == 10

        # Check stock updated correctly
        resp = await client.get(f"/medicines/{med_id}", headers=headers)
        new_stock = resp.json()["quantity_in_stock"]
        assert new_stock == 20

        # Record sale exceeding stock
        sale_data = {"medicine_id": med_id, "quantity_sold": 25}
        resp = await client.post("/sales/", json=sale_data, headers=headers)
        assert resp.status_code == 400

@pytest.mark.asyncio
async def test_inventory_status_endpoint():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        await client.post("/users/", json={"username": "invuser", "password": "invpass123"})
        login_resp = await client.post("/token", data={"username": "invuser", "password": "invpass123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Add medicines with varying stock and expiry dates
        meds = [
            {
                "name": "MedLowStock",
                "batch_number": "LOW1",
                "expiry_date": (date.today() + timedelta(days=100)).isoformat(),
                "price": 10,
                "quantity_in_stock": 5,  # low stock < 10
            },
            {
                "name": "MedExpiringSoon",
                "batch_number": "EXP1",
                "expiry_date": (date.today() + timedelta(days=5)).isoformat(),  # expiring within 30 days
                "price": 20,
                "quantity_in_stock": 50,
            },
            {
                "name": "MedNormal",
                "batch_number": "NORM1",
                "expiry_date": (date.today() + timedelta(days=100)).isoformat(),
                "price": 30,
                "quantity_in_stock": 50,
            },
        ]

        for med in meds:
            await client.post("/medicines/", json=med, headers=headers)

        resp = await client.get("/inventory/status/", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

        # low_stock should include MedLowStock but not MedNormal
        low_stock_names = [m["name"] for m in data["low_stock"]]
        assert "MedLowStock" in low_stock_names
        assert "MedNormal" not in low_stock_names

        # expiring_soon should include MedExpiringSoon but not MedNormal
        expiring_names = [m["name"] for m in data["expiring_soon"]]
        assert "MedExpiringSoon" in expiring_names
        assert "MedNormal" not in expiring_names
