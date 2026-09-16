"""UI-only preview: no database, credentials, or external service connections."""

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from saas.control_plane.onboarding_http import create_onboarding_ui_router

app = FastAPI()
app.include_router(create_onboarding_ui_router())


@app.post("/saas/auth/login")
def preview_login() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "detail": {
                "message": "UI preview only. No credentials were submitted to a live service."
            }
        },
    )
