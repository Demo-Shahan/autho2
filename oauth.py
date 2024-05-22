from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import pathlib
import os


app = FastAPI()  # docs_url=None, redoc_url=None

############################################################## Authentication SSO ##################################
app.secret_key = "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" # make sure this matches with that's in client_secret.json
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev

GOOGLE_CLIENT_ID = "1019911793171-pipdaeturnnp4g6h38mes12hemukfa5u.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://autho2.onrender.com/callback"
)

app.add_middleware(SessionMiddleware, secret_key=app.secret_key)

# Dependency to get the session
def get_session(request: Request):
    return request.session


def login_is_required(session: dict = Depends(get_session)):
    if "google_id" not in session:
        raise HTTPException(status_code=401, detail="Authorization required")


@app.get("/login")
async def login(request: Request):
    authorization_url, state = flow.authorization_url()
    request.session["state"] = state
    return RedirectResponse(authorization_url)

@app.get("/callback")
async def callback(request: Request, session: dict = Depends(get_session)):
    # flow = get_flow()

    flow.fetch_token(authorization_response=str(request.url))

    if not request.session["state"] == request.query_params["state"]:
        print('\n\ncqllback Exception\n\n')
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="State does not match!")

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    request.session["google_id"] = id_info.get("sub")
    request.session["name"] = id_info.get("name")
    request.session["email"] = id_info.get("email")

    email = request.session["email"]
    name = request.session["name"]
    url = f"https://calldev.sentrihub.com/?name={name}&email={email}"

    return RedirectResponse(url=url)




# Run the FastAPI app using Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
