import secrets
import sqlite3

import io

from werkzeug.utils import secure_filename

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    send_file as flask_send_file,
    url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from crypto_utils import (
    decrypt_private_key,
    decrypt_received_message,
    encrypt_for_recipient,
    encrypt_private_key,
    generate_user_key_pair,
    load_public_key_from_bytes,
    sign_message,
    decrypt_received_file,
    encrypt_file_for_recipient,
    verify_signature
)
from database import get_connection, initialize_database


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

# Used to protect login session cookies.
# For the project prototype, this generates a new secret when the app starts.
app.secret_key = secrets.token_hex(32)

initialize_database()


def generate_cipherlink_id():
    """
    Generates an anonymous ID such as:
    CL-7F3A-92D1
    """

    while True:
        random_part = secrets.token_hex(4).upper()

        cipherlink_id = (
            f"CL-{random_part[:4]}-{random_part[4:]}"
        )

        with get_connection() as connection:
            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE cipherlink_id = ?
                """,
                (cipherlink_id,)
            ).fetchone()

        if existing_user is None:
            return cipherlink_id


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username:
            flash("Please enter a username.", "error")
            return render_template("register.html")

        if len(username) < 3:
            flash(
                "Username must contain at least 3 characters.",
                "error"
            )
            return render_template("register.html")

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        # Generate the user's RSA key pair.
        private_key_bytes, public_key_bytes = (
            generate_user_key_pair()
        )

        # Protect the private key using the user's password.
        encrypted_private_key, private_key_salt = (
            encrypt_private_key(
                private_key_bytes,
                password
            )
        )

        cipherlink_id = generate_cipherlink_id()

        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        cipherlink_id,
                        username,
                        password_hash,
                        public_key,
                        encrypted_private_key,
                        private_key_salt
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cipherlink_id,
                        username,
                        password_hash,
                        public_key_bytes,
                        encrypted_private_key,
                        private_key_salt
                    )
                )

                connection.commit()
                user_id = cursor.lastrowid

        except sqlite3.IntegrityError:
            flash(
                "That username is already being used.",
                "error"
            )
            return render_template("register.html")

        session.clear()
        session["user_id"] = user_id
        session["cipherlink_id"] = cipherlink_id
        session["username"] = username

        flash(
            "Your CipherLink account was created successfully.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_connection() as connection:
            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        if user is None:
            flash("Incorrect username or password.", "error")
            return render_template("login.html")

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            flash("Incorrect username or password.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["cipherlink_id"] = user["cipherlink_id"]
        session["username"] = user["username"]

        flash("Login successful.", "success")

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    with get_connection() as connection:
        incoming_requests = connection.execute(
            """
            SELECT
                contact_requests.id,
                users.cipherlink_id AS sender_cipherlink_id
            FROM contact_requests
            JOIN users
                ON users.id = contact_requests.sender_id
            WHERE contact_requests.receiver_id = ?
              AND contact_requests.status = 'pending'
            ORDER BY contact_requests.created_at DESC
            """,
            (user_id,)
        ).fetchall()

        contacts = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                users.cipherlink_id
            FROM contacts
            JOIN users
                ON users.id = CASE
                    WHEN contacts.user_one_id = ?
                    THEN contacts.user_two_id
                    ELSE contacts.user_one_id
                END
            WHERE contacts.user_one_id = ?
               OR contacts.user_two_id = ?
            ORDER BY contacts.created_at DESC
            """,
            (user_id, user_id, user_id)
        ).fetchall()

    return render_template(
        "dashboard.html",
        username=session["username"],
        cipherlink_id=session["cipherlink_id"],
        incoming_requests=incoming_requests,
        contacts=contacts
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/search-user", methods=["POST"])
def search_user():
    if "user_id" not in session:
        return redirect(url_for("login"))

    searched_id = request.form.get("cipherlink_id", "").strip().upper()

    if not searched_id:
        flash("Enter a CipherLink ID.", "error")
        return redirect(url_for("dashboard"))

    if searched_id == session["cipherlink_id"]:
        flash("You cannot search for yourself.", "error")
        return redirect(url_for("dashboard"))

    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT id, cipherlink_id
            FROM users
            WHERE cipherlink_id = ?
            """,
            (searched_id,)
        ).fetchone()

    if user is None:
        flash("No account was found with that exact ID.", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "search_result.html",
        found_user=user
    )


@app.route("/send-request/<int:receiver_id>", methods=["POST"])
def send_request(receiver_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    sender_id = session["user_id"]

    if sender_id == receiver_id:
        flash("You cannot send a request to yourself.", "error")
        return redirect(url_for("dashboard"))

    with get_connection() as connection:
        existing_request = connection.execute(
            """
            SELECT id
            FROM contact_requests
            WHERE sender_id = ?
              AND receiver_id = ?
              AND status = 'pending'
            """,
            (sender_id, receiver_id)
        ).fetchone()

        if existing_request:
            flash("You already sent this user a request.", "error")
            return redirect(url_for("dashboard"))

        connection.execute(
            """
            INSERT INTO contact_requests (
                sender_id,
                receiver_id,
                status
            )
            VALUES (?, ?, 'pending')
            """,
            (sender_id, receiver_id)
        )

        connection.commit()

    flash("Messaging request sent successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/accept-request/<int:request_id>", methods=["POST"])
def accept_request(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    with get_connection() as connection:
        request_row = connection.execute(
            """
            SELECT id, sender_id, receiver_id, status
            FROM contact_requests
            WHERE id = ?
            """,
            (request_id,)
        ).fetchone()

        if request_row is None:
            flash("That request no longer exists.", "error")
            return redirect(url_for("dashboard"))

        if request_row["receiver_id"] != current_user_id:
            flash("You are not allowed to accept this request.", "error")
            return redirect(url_for("dashboard"))

        if request_row["status"] != "pending":
            flash("This request has already been handled.", "error")
            return redirect(url_for("dashboard"))

        user_one_id = min(
            request_row["sender_id"],
            request_row["receiver_id"]
        )
        user_two_id = max(
            request_row["sender_id"],
            request_row["receiver_id"]
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO contacts (
                user_one_id,
                user_two_id
            )
            VALUES (?, ?)
            """,
            (user_one_id, user_two_id)
        )

        connection.execute(
            """
            UPDATE contact_requests
            SET status = 'accepted'
            WHERE id = ?
            """,
            (request_id,)
        )

        connection.commit()

    flash("Messaging request accepted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/chat/<int:contact_id>")
def chat(contact_id):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    with get_connection() as connection:
        contact = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                users.cipherlink_id
            FROM contacts
            JOIN users
                ON users.id = CASE
                    WHEN contacts.user_one_id = ?
                    THEN contacts.user_two_id
                    ELSE contacts.user_one_id
                END
            WHERE
                (contacts.user_one_id = ? OR contacts.user_two_id = ?)
                AND users.id = ?
            """,
            (
                current_user_id,
                current_user_id,
                current_user_id,
                contact_id
            )
        ).fetchone()

        if contact is None:
            flash("You are not connected with that user.", "error")
            return redirect(url_for("dashboard"))

        messages = connection.execute(
            """
            SELECT
                messages.id,
                messages.sender_id,
                messages.recipient_id,
                messages.ciphertext,
                messages.created_at,
                users.username AS sender_username
            FROM messages
            JOIN users
                ON users.id = messages.sender_id
            WHERE
                (messages.sender_id = ? AND messages.recipient_id = ?)
                OR
                (messages.sender_id = ? AND messages.recipient_id = ?)
            ORDER BY messages.created_at ASC
            """,
            (
                current_user_id,
                contact_id,
                contact_id,
                current_user_id
            )
        ).fetchall()


        file_transfers = connection.execute(
            """
            SELECT
                file_transfers.id,
                file_transfers.sender_id,
                file_transfers.recipient_id,
                file_transfers.original_filename,
                file_transfers.encrypted_file,
                file_transfers.created_at,
                users.username AS sender_username
            FROM file_transfers
            JOIN users
                ON users.id = file_transfers.sender_id
            WHERE
                (
                    file_transfers.sender_id = ?
                    AND file_transfers.recipient_id = ?
                )
                OR
                (
                    file_transfers.sender_id = ?
                    AND file_transfers.recipient_id = ?
                )
            ORDER BY file_transfers.created_at ASC
            """,
            (
                current_user_id,
                contact_id,
                contact_id,
                current_user_id
            )
        ).fetchall()

    decrypted_messages = {}
    signature_results = {}

    for message in messages:
        message_id = message["id"]

        decrypted_messages[message_id] = session.get(
            f"decrypted_message_{message_id}"
        )

        signature_results[message_id] = session.get(
            f"signature_valid_{message_id}"
        )

    return render_template(
        "chat_v2.html",
        contact=contact,
        messages=messages,
        current_user_id=current_user_id,
        decrypted_messages=decrypted_messages,
        file_transfers=file_transfers,
        signature_results=signature_results
    )


@app.route("/send-message/<int:recipient_id>", methods=["POST"])
def send_message(recipient_id):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    sender_id = session["user_id"]
    message_text = request.form.get("message", "").strip()
    password = request.form.get("password", "")

    if not message_text:
        flash("Message cannot be empty.", "error")
        return redirect(url_for("chat", contact_id=recipient_id))

    if not password:
        flash("Enter your account password to sign the message.", "error")
        return redirect(url_for("chat", contact_id=recipient_id))

    with get_connection() as connection:
        sender = connection.execute(
            """
            SELECT
                password_hash,
                encrypted_private_key,
                private_key_salt
            FROM users
            WHERE id = ?
            """,
            (sender_id,)
        ).fetchone()

        recipient = connection.execute(
            """
            SELECT public_key
            FROM users
            WHERE id = ?
            """,
            (recipient_id,)
        ).fetchone()

        contact_exists = connection.execute(
            """
            SELECT id
            FROM contacts
            WHERE
                (user_one_id = ? AND user_two_id = ?)
                OR
                (user_one_id = ? AND user_two_id = ?)
            """,
            (
                sender_id,
                recipient_id,
                recipient_id,
                sender_id
            )
        ).fetchone()

        if sender is None or recipient is None or contact_exists is None:
            flash("You cannot message this user.", "error")
            return redirect(url_for("dashboard"))

        if not check_password_hash(
            sender["password_hash"],
            password
        ):
            flash("Incorrect password.", "error")
            return redirect(url_for("chat", contact_id=recipient_id))

        try:
            private_key = decrypt_private_key(
                sender["encrypted_private_key"],
                password,
                sender["private_key_salt"]
            )
        except Exception:
            flash("Could not unlock your private key.", "error")
            return redirect(url_for("chat", contact_id=recipient_id))

        ciphertext, encrypted_key = encrypt_for_recipient(
            recipient["public_key"],
            message_text
        )

        signature = sign_message(
            private_key,
            ciphertext
        )

        connection.execute(
            """
            INSERT INTO messages (
                sender_id,
                recipient_id,
                ciphertext,
                encrypted_key,
                signature
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sender_id,
                recipient_id,
                ciphertext,
                encrypted_key,
                signature
            )
        )

        connection.commit()

    flash("Encrypted message sent successfully.", "success")
    return redirect(url_for("chat", contact_id=recipient_id))

@app.route("/decrypt-message/<int:message_id>", methods=["POST"])
def decrypt_message_route(message_id):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    current_user_id = session["user_id"]
    password = request.form.get("password", "")

    if not password:
        flash("Enter your account password.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    with get_connection() as connection:
        message = connection.execute(
            """
            SELECT
                messages.*,
                sender.public_key AS sender_public_key
            FROM messages
            JOIN users AS sender
                ON sender.id = messages.sender_id
            WHERE messages.id = ?
            """,
            (message_id,)
        ).fetchone()

        current_user = connection.execute(
            """
            SELECT
                password_hash,
                encrypted_private_key,
                private_key_salt
            FROM users
            WHERE id = ?
            """,
            (current_user_id,)
        ).fetchone()

    if message is None:
        flash("Message not found.", "error")
        return redirect(url_for("dashboard"))

    if message["recipient_id"] != current_user_id:
        flash("You are not allowed to decrypt this message.", "error")
        return redirect(url_for("dashboard"))

    if not check_password_hash(
        current_user["password_hash"],
        password
    ):
        flash("Incorrect password.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    try:
        private_key = decrypt_private_key(
            current_user["encrypted_private_key"],
            password,
            current_user["private_key_salt"]
        )

        plaintext = decrypt_received_message(
            private_key,
            message["encrypted_key"],
            message["ciphertext"]
        )

        sender_public_key = load_public_key_from_bytes(
            message["sender_public_key"]
        )

        signature_valid = verify_signature(
            sender_public_key,
            message["ciphertext"],
            message["signature"]
        )

    except Exception:
        flash("Decryption failed.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    session[f"decrypted_message_{message_id}"] = plaintext
    session[f"signature_valid_{message_id}"] = signature_valid

    return redirect(request.referrer or url_for("dashboard"))
    
@app.route("/send-file/<int:recipient_id>", methods=["POST"])
def send_file(recipient_id):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    sender_id = session["user_id"]
    uploaded_file = request.files.get("file")
    password = request.form.get("file_password", "")

    if uploaded_file is None or uploaded_file.filename == "":
        flash("Please select a file.", "error")
        return redirect(url_for("chat", contact_id=recipient_id))

    if not password:
        flash(
            "Enter your account password to sign and send the file.",
            "error"
        )
        return redirect(url_for("chat", contact_id=recipient_id))

    filename = secure_filename(uploaded_file.filename)

    if not filename:
        flash("That filename is not valid.", "error")
        return redirect(url_for("chat", contact_id=recipient_id))

    file_bytes = uploaded_file.read()

    if not file_bytes:
        flash("The selected file is empty.", "error")
        return redirect(url_for("chat", contact_id=recipient_id))

    with get_connection() as connection:
        sender = connection.execute(
            """
            SELECT
                password_hash,
                encrypted_private_key,
                private_key_salt
            FROM users
            WHERE id = ?
            """,
            (sender_id,)
        ).fetchone()

        recipient = connection.execute(
            """
            SELECT public_key
            FROM users
            WHERE id = ?
            """,
            (recipient_id,)
        ).fetchone()

        contact_exists = connection.execute(
            """
            SELECT id
            FROM contacts
            WHERE
                (user_one_id = ? AND user_two_id = ?)
                OR
                (user_one_id = ? AND user_two_id = ?)
            """,
            (
                sender_id,
                recipient_id,
                recipient_id,
                sender_id
            )
        ).fetchone()

        if sender is None or recipient is None or contact_exists is None:
            flash("You cannot send files to this user.", "error")
            return redirect(url_for("dashboard"))

        if not check_password_hash(
            sender["password_hash"],
            password
        ):
            flash("Incorrect password.", "error")
            return redirect(url_for("chat", contact_id=recipient_id))

        try:
            private_key = decrypt_private_key(
                sender["encrypted_private_key"],
                password,
                sender["private_key_salt"]
            )
        except Exception:
            flash("Could not unlock your private key.", "error")
            return redirect(url_for("chat", contact_id=recipient_id))

        encrypted_file, encrypted_key = encrypt_file_for_recipient(
            recipient["public_key"],
            file_bytes
        )

        signed_data = filename.encode("utf-8") + encrypted_file

        signature = sign_message(
            private_key,
            signed_data
        )

        connection.execute(
            """
            INSERT INTO file_transfers (
                sender_id,
                recipient_id,
                original_filename,
                encrypted_file,
                encrypted_key,
                signature
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sender_id,
                recipient_id,
                filename,
                encrypted_file,
                encrypted_key,
                signature
            )
        )

        connection.commit()

    flash("Encrypted file sent successfully.", "success")
    return redirect(url_for("chat", contact_id=recipient_id))

@app.route("/decrypt-file/<int:file_id>", methods=["POST"])
def decrypt_file_route(file_id):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    current_user_id = session["user_id"]
    password = request.form.get("password", "")

    if not password:
        flash("Enter your account password.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    with get_connection() as connection:
        file_item = connection.execute(
            """
            SELECT
                file_transfers.*,
                sender.public_key AS sender_public_key
            FROM file_transfers
            JOIN users AS sender
                ON sender.id = file_transfers.sender_id
            WHERE file_transfers.id = ?
            """,
            (file_id,)
        ).fetchone()

        current_user = connection.execute(
            """
            SELECT
                password_hash,
                encrypted_private_key,
                private_key_salt
            FROM users
            WHERE id = ?
            """,
            (current_user_id,)
        ).fetchone()

    if file_item is None:
        flash("File transfer not found.", "error")
        return redirect(url_for("dashboard"))

    if file_item["recipient_id"] != current_user_id:
        flash("You are not allowed to decrypt this file.", "error")
        return redirect(url_for("dashboard"))

    if not check_password_hash(
        current_user["password_hash"],
        password
    ):
        flash("Incorrect password.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    try:
        private_key = decrypt_private_key(
            current_user["encrypted_private_key"],
            password,
            current_user["private_key_salt"]
        )

        decrypted_file = decrypt_received_file(
            private_key,
            file_item["encrypted_key"],
            file_item["encrypted_file"]
        )

        sender_public_key = load_public_key_from_bytes(
            file_item["sender_public_key"]
        )

        signed_data = (
            file_item["original_filename"].encode("utf-8")
            + file_item["encrypted_file"]
        )

        signature_valid = verify_signature(
            sender_public_key,
            signed_data,
            file_item["signature"]
        )

        if not signature_valid:
            flash(
                "File signature verification failed. Download blocked.",
                "error"
            )
            return redirect(request.referrer or url_for("dashboard"))

    except Exception:
        flash("File decryption failed.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    return flask_send_file(
        io.BytesIO(decrypted_file),
        as_attachment=True,
        download_name=file_item["original_filename"]
    )

    
@app.route("/reject-request/<int:request_id>", methods=["POST"])
def reject_request(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    with get_connection() as connection:
        request_row = connection.execute(
            """
            SELECT id, receiver_id, status
            FROM contact_requests
            WHERE id = ?
            """,
            (request_id,)
        ).fetchone()

        if request_row is None:
            flash("That request no longer exists.", "error")
            return redirect(url_for("dashboard"))

        if request_row["receiver_id"] != current_user_id:
            flash("You are not allowed to reject this request.", "error")
            return redirect(url_for("dashboard"))

        if request_row["status"] != "pending":
            flash("This request has already been handled.", "error")
            return redirect(url_for("dashboard"))

        connection.execute(
            """
            UPDATE contact_requests
            SET status = 'rejected'
            WHERE id = ?
            """,
            (request_id,)
        )

        connection.commit()

    flash("Messaging request rejected.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)