from flask import Flask, render_template, request
from crypto_utils import (
    encrypt_message,
    sign_message,
    verify_signature,
    load_private_key,
    load_public_key
)

app = Flask(__name__)

messages = []

@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        sender = request.form["sender"]
        text = request.form["message"]

        if sender == "Fatima":
            private_key = load_private_key("keys/fatima_private.pem")
            public_key = load_public_key("keys/fatima_public.pem")
        else:
            private_key = load_private_key("keys/ammara_private.pem")
            public_key = load_public_key("keys/ammara_public.pem")

        encrypted = encrypt_message(text)

        signature = sign_message(
            private_key,
            text.encode()
        )

        verified = verify_signature(
            public_key,
            text.encode(),
            signature
        )

        messages.append({
            "sender": sender,
            "message": text,
            "encrypted": encrypted.decode(),
            "signature": signature.hex(),
            "verified": verified
        })

    return render_template(
        "chat.html",
        messages=messages
    )

if __name__ == "__main__":
    app.run(debug=True)