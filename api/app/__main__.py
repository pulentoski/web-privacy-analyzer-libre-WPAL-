import uvicorn

from app.logging_setup import configure_logging

if __name__ == "__main__":
    configure_logging()
    # log_config=None: uvicorn usa el logging JSON ya configurado.
    # access_log=False: el acceso lo registra el middleware de app.main.
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, log_config=None, access_log=False)
