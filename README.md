# MedSupply360 🩺

MedSupply360 is a full-featured backend API for managing pharmacy inventory, tracking sales, and forecasting restocks. Designed to streamline medicine management, this project powers medicine intake, expiry alerts, and sales dashboards.

## 💡 Features

- ✅ Add/edit/delete medicines with batch number, expiry date, and quantity
- 📦 Stock alert system for low inventory
- ⏳ Expiry alerts based on date proximity
- 📈 Sales tracking and forecasting via `/forecast` endpoint
- 🧪 API tested with `pytest` and Postman
- 🔐 JWT-based user authentication

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI (async)
- **Database:** MySQL (with raw SQL queries and async support)
- **Auth:** JWT (JSON Web Tokens)
- **Testing:** Unittest, Pytest
- **Deployment:** In progress (Render)

## 📂 API Endpoints (sample)

- `POST /medicines` – Add a new medicine
- `GET /medicines` – View all medicines
- `GET /alerts` – View low stock & expiring items
- `POST /sales` – Record a sale
- `GET /forecast` – Get sales forecast (WIP)

## 📸 Screenshots

![Dashboard Example](assets/dashboard.png)
![Alerts](assets/alerts.png)

## 🚀 Getting Started

```bash
git clone https://github.com/LaurianeH-05/MedSupply360.git
cd MedSupply360
pip install -r requirements.txt
uvicorn main:app --reload
