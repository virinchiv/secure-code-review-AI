from fastapi import FastAPI
from backend.routes import review

app = FastAPI(title = "SentinelAI")
app.include_router(review.router, prefix="/review")

@app.get("/")
async def root():
    return {"message": "Welcome to SentinelAI Secure Code Review Agent"}