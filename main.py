from evidence_protector_api import app


if __name__ == "__main__":
    import os
    import uvicorn

    host = os.getenv("EVIDENCE_PROTECTOR_API_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("EVIDENCE_PROTECTOR_API_PORT", "8000")))
    uvicorn.run(app, host=host, port=port)
