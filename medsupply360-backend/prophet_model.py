from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from fastapi.concurrency import run_in_threadpool
from typing import List
import pandas as pd
from prophet import Prophet

router = APIRouter()

class DataPoint(BaseModel):
    ds: str
    y: float

class ForecastRequest(BaseModel):
    data: List[DataPoint]
    periods: int = 30

@router.post("/forecast")
async def forecast(request: ForecastRequest):
    if len(request.data) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 data points.")

    df = pd.DataFrame([d.dict() for d in request.data])
    df['ds'] = pd.to_datetime(df['ds'])

    def run_prophet():
        model = Prophet(yearly_seasonality=True, weekly_seasonality=True)
        model.fit(df)
        future = model.make_future_dataframe(periods=request.periods)
        forecast = model.predict(future)
        return forecast[['ds', 'yhat', 'yhat_lower', 'yhat_upper']].tail(request.periods).to_dict(orient='records')

    result = await run_in_threadpool(run_prophet)
    return {"forecast": result}
