import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
import joblib
import re
import base64
import pickle
import secrets
from bs4 import BeautifulSoup
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Load your trained model and vectorizer
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

label_map = {0: "Phishing", 1: "Ham"}
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# ===== Utility functions =====
def clean_email(text):
    text = re.sub(r'http\S+|www\S+|https\S+', "", text, flags=re.MULTILINE)
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_email_body(payload):
    """Extract plain text from Gmail message payload."""
    if payload.get("body") and payload["body"].get("data"):
        data = payload["body"]["data"]
        decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        return BeautifulSoup(decoded, "html.parser").get_text()
    elif "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                return get_email_body(part)
        for part in payload["parts"]:
            if part.get("mimeType") == "text/html":
                html = get_email_body(part)
                return BeautifulSoup(html, "html.parser").get_text()
    return ""

# ===== Flask routes =====
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    email_text = request.form["email"]
    cleaned = clean_email(email_text)
    vectorized = vectorizer.transform([cleaned])
    prediction = model.predict(vectorized)[0]
    result = label_map[prediction]
    return render_template("index.html", prediction=result)

@app.route("/authorize")
def authorize():
    creds_dict = json.loads(os.environ["GOOGLE_CREDENTIALS"])  # Load from env
    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')  # Force HTTPS
    client_id = creds_dict['web']['client_id']

    print("Redirect URI being sent (authorize):", redirect_uri)  # DEBUG
    print("Client ID being used (authorize):", client_id)       # DEBUG

    flow = Flow.from_client_config(
        creds_dict,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    creds_dict = json.loads(os.environ["GOOGLE_CREDENTIALS"])
    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')  # Force HTTPS

    print("Redirect URI being sent (callback):", redirect_uri)  # DEBUG

    flow = Flow.from_client_config(
        creds_dict,
        scopes=SCOPES,
        state=session['state'],
        redirect_uri=redirect_uri
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session['credentials'] = pickle.dumps(creds)
    return redirect(url_for('check_gmail'))

@app.route("/check_gmail")
def check_gmail():
    creds = pickle.loads(session['credentials'])
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(
        userId='me',
        labelIds=['INBOX'],
        maxResults=5
    ).execute()
    messages = results.get('messages', [])
    output = []

    for msg in messages:
        msg_data = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='full'
        ).execute()
        payload = msg_data['payload']
        subject = next((h['value'] for h in payload['headers'] if h['name'] == 'Subject'), "(No Subject)")
        email_body = get_email_body(payload)

        if email_body:
            cleaned = clean_email(email_body)
            features = vectorizer.transform([cleaned])
            prediction = model.predict(features)[0]
            pred_label = label_map[prediction]
            output.append((subject, pred_label))
        else:
            output.append((subject, "No email body found"))

    return render_template("index.html", gmail_results=output)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    if os.environ.get("RENDER"):
        app.run(host="0.0.0.0", port=port, debug=False)
    else:
        app.run(host="0.0.0.0", port=port, ssl_context="adhoc", debug=True)
