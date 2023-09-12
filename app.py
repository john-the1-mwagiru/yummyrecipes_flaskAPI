from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_mail import Mail, Message
from functools import wraps
from marshmallow import Schema, fields
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from models import (
    Users,
    UserSchema,
    db,
    Categories,
    CategorySchema,
    Recipes,
    RecipeSchema,
)
import datetime
import jwt
import re


app = Flask(__name__)
app.config["SECRET_KEY"] = "asecret"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres:Kenya2030**@localhost:5433/Yummy Recipes"
migrate = Migrate(app, db)
db.init_app(app)
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
app.config.update(
    dict(
        DEBUG=True,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_USERNAME="john.the1.mwagiru@gmail.com",
        MAIL_PASSWORD="fbvvwlltrhicvicv",
    )
)
mail = Mail(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return (
                jsonify({"message": "Authentication Token is missing!", "data": None}),
                401,
            )
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = Users.query.get(data["userid"])
        except Exception as e:
            return jsonify({"message": "Something went wrong"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


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


@app.route("/auth/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )
    user = Users.query.filter_by(name=auth.username).first()
    if not user:
        return jsonify({"message": "No user found!"})
    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode(
            {
                "userid": user.id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
        )
        return jsonify({"token": token})
    return make_response(
        "Could not verify",
        401,
        {"WWW-Authenticate": 'Basic realm="Login required!"'},
    )


@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        email = request.json["email"]
        if Users.query.filter_by(email=request.json["email"]).first() is None:
            return jsonify({"error": "Email does not exist!"}), 400

        token = s.dumps(email, salt="recovery-key")
        link = "http://localhost:5000/reset-password/"
        msg = Message(
            f"Hello from the other side!",
            sender="john.the1.mwagiru@gmail.com",
            recipients=[email],
        )
        msg.body = f"Hey, follow this {link}{token} to reset your password"
        mail.send(msg)
        return jsonify({"token": token}), 200


@app.route("/auth/reset-password/<token>", methods=["POST"])
def reset_password(token):
    password = request.json["password_hash"]
    try:
        email = s.loads(token, salt="recovery-key", max_age=60 * 10)
        user = Users.query.filter(Users.email == email)

        if user:
            for auser in user:
                auser.password_hash = generate_password_hash(password, method="sha256")
                db.session.commit()
                serializer = UserSchema()
                data = serializer.dump(auser)
                return jsonify(data), 200
        if not user:
            return jsonify({"error": "error"}), 400
    except:
        return jsonify({"error": "no user"}), 400


@app.route("/categories", methods=["GET"])
@token_required
def get_all_categories(current_user):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    categories = [
        category
        for category in Categories.get_all()
        if category.user_id == data["userid"]
    ]
    serializer = CategorySchema(many=True)
    new_data = serializer.dump(categories)

    return jsonify(new_data)


@app.route("/categories", methods=["POST"])
@token_required
def create_categories(current_user):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    if Categories.query.filter_by(name=request.json["name"]).first() is None:
        new_category = Categories(
            name=request.json["name"],
            description=request.json["description"],
            user_id=data["userid"],
        )
        new = Categories.create(new_category)
        serializer = CategorySchema()
        newcategory = serializer.dump(new)
        return jsonify(newcategory), 200
    return jsonify({"error": "category name already exists"})


@app.route("/categories/<int:id>", methods=["GET"])
@token_required
def get_category(current_user, id):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    categories = Categories.query.filter(Categories.user_id == data["userid"])
    for category in categories:
        if category.id == id:
            serializer = CategorySchema()
            acategory = serializer.dump(category)
            return jsonify(acategory), 200
    return jsonify({"error": "category does not exist"}), 400


@app.route("/categories/<int:id>/edit", methods=["PUT"])
@token_required
def edit_category(current_user, id):
    edited_name = request.json["name"]
    edited_description = request.json["description"]
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    categories = Categories.query.filter(Categories.user_id == data["userid"])
    for category in categories:
        if category.id == id:
            edited_category = Categories(
                id=category.id,
                name=edited_name,
                description=edited_description,
                user_id=category.user_id,
            )
            updated_category = Categories.edit(id, edited_category)
            serializer = CategorySchema()
            new_data = serializer.dump(updated_category)
            return jsonify(new_data), 200
    return jsonify({"error": "category does not exist"}), 400


@app.route("/categories/<int:id>/delete", methods=["DELETE"])
def delete_category(id):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    categories = Categories.query.filter(Categories.user_id == data["userid"])
    for category in categories:
        if category.id == id:
            Categories.delete(id)
            return jsonify({"message": "Category was successfully deleted"}), 200
    return jsonify({"error": "category was not found"}), 400


@app.route("/recipes", methods=["POST"])
@token_required
def create_recipes(current_user):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    if Recipes.query.filter_by(name=request.json["name"]).first() is None:
        new_recipe = Recipes(
            name=request.json["name"],
            ingredients=request.json["ingredients"],
            directions=request.json["directions"],
            category_id=request.json["category_id"],
            user_id=data["userid"],
        )
        serializer = RecipeSchema()
        newrecipe = serializer.dump(Recipes.create(new_recipe))
        return jsonify(newrecipe), 201
    return jsonify({"error": "something came up!"}), 400


@app.route("/recipes", methods=["GET"])
@token_required
def get_all_recipes(current_user):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 3, type=int)
    recipes = Recipes.query.filter_by(user_id=data["userid"]).paginate(
        page=page, per_page=per_page
    )
    serializer = RecipeSchema(many=True)
    all_recipes = serializer.dump(recipes)

    meta = {
        "page": recipes.page,
        "pages": recipes.pages,
        "total_count": recipes.total,
        "prev_page": recipes.prev_num,
        "next_page": recipes.next_num,
        "has_next": recipes.has_next,
        "has_prev": recipes.has_prev,
    }
    return jsonify(all_recipes, meta), 200


@app.route("/recipes/<int:id>", methods=["GET"])
@token_required
def get_recipe(current_user, id):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    recipes = Recipes.query.filter(Recipes.user_id == data["userid"])
    for recipe in recipes:
        if recipe.id == id:
            serializer = RecipeSchema()
            arecipe = serializer.dump(recipe)
            return jsonify(arecipe), 200
    return jsonify({"error": "recipe was not found"}), 404


@app.route("/recipes/<int:id>/edit", methods=["PUT"])
@token_required
def edit_recipe(current_user, id):
    edited_name = request.json["name"]
    edited_ingredients = request.json["ingredients"]
    edited_directions = request.json["directions"]
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    recipes = Recipes.query.filter(Recipes.user_id == data["userid"])
    for recipe in recipes:
        if recipe.id == id:
            edited_recipe = Recipes(
                id=recipe.id,
                name=edited_name,
                ingredients=edited_ingredients,
                directions=edited_directions,
                category_id=recipe.category_id,
                user_id=recipe.user_id,
            )
            serializer = RecipeSchema()
            new_data = serializer.dump(Recipes.edit(id, edited_recipe))
            return jsonify(new_data), 200
    return jsonify({"error": "something went wrong!"}), 400


@app.route("/recipes/<int:id>/delete", methods=["DELETE"])
def delete_recipe(id):
    token = request.headers["x-access-token"]
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    recipes = Recipes.query.filter(Recipes.user_id == data["userid"])
    for recipe in recipes:
        if recipe.id == id:
            Recipes.delete(id)
            return jsonify({"message": "Recipe was successfully deleted"}), 200
    return jsonify({"error": "recipe was not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
