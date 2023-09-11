from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from marshmallow import Schema, fields
import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "asecret"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres:Kenya2030**@localhost:5433/Yummy Recipes"
app.app_context().push()
db = SQLAlchemy(app)
migrate = Migrate(app, db)


@app.route("/")
def hello():
    return {"hello": "world"}


if __name__ == "__main__":
    app.run(debug=True)
