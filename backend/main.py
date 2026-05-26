from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import scanner

app = FastAPI(
    title="Web Vulnerability Scanner",
    description="Scanner de vulnerabilidades na camada de aplicação web.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scanner.router, prefix="/api/v1")


@app.get("/")
def root():
    return {"status": "ok", "message": "Web Vulnerability Scanner API"}
