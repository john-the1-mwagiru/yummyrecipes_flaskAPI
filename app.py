from flask import Flask, jsonify, request
from flask_migrate import Migrate
from marshmallow import Schema, fields
from werkzeug.security import generate_password_hash, check_password_hash
from models import Users, UserSchema, db
import datetime
import re

app = Flask(__name__)
app.config["SECRET_KEY"] = "asecret"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres:Kenya2030**@localhost:5433/Yummy Recipes"
# migrate = Migrate(app, db)
db.init_app(app)
email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"


@app.route("/auth/register", methods=["POST"])
def register():
    username = request.json["name"]
    email = request.json["email"]
    password_hash = request.json["password"]

    if len(password_hash) < 6:
        return jsonify({"error": "Password is too short"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username is too short"}), 400

    if not username.isalnum() or " " in username:
        return jsonify({"error": "Username should be alphanumeric "}), 400

    if not re.fullmatch(email_regex, email) or not email:
        return jsonify({"error": "Email format is invalid!"}), 400

    if Users.query.filter_by(email=request.json["email"]).first() is not None:
        return jsonify({"error": "Email already exists!"}), 409

    if Users.query.filter_by(name=request.json["name"]).first() is not None:
        return jsonify({"error": "Username already exists!"}), 409

    pwd_hash = generate_password_hash(password_hash)
    new_user = Users(
        name=username,
        email=email,
        password_hash=generate_password_hash(password_hash, method="sha256"),
    )
    Users.create(new_user)
    serializer = UserSchema()
    data = serializer.dump(new_user)
    return jsonify(data), 201


if __name__ == "__main__":
    app.run(debug=True)
