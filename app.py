from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_restful import Api, Resource
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
    Blacklist,
)
import datetime
import jwt
import re


app = Flask(__name__)
app.config["SECRET_KEY"] = "asecret"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres_:fl4pXyoFluiDzQZKHF5cYCCoaJcyuRBO@dpg-ckamsucg66mc73861gj0-a.oregon-postgres.render.com/yummy_recipes"
migrate = Migrate(app, db)
api = Api(app)
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
        check_token = Blacklist.query.filter_by(revoked_token=token).first()
        if check_token:
            return {"message": "Session not available,Please log in"}, 401
        if not token:
            return (
                {"message": "Authentication Token is missing!", "data": None},
                401,
            )

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = Users.query.get(data["userid"])
        except Exception as e:
            return {"message": "Something went wrong"}, 401

        return f(current_user, *args, **kwargs)

    return decorated


class RegisterUser(Resource):
    def post(self):
        username = request.json["name"]
        email = request.json["email"]
        password_hash = request.json["password"]

        if len(password_hash) < 6:
            return {"error": "Password is too short"}, 400

        if len(username) < 3:
            return {"error": "Username is too short"}, 400

        if not username.isalnum() or " " in username:
            return {"error": "Username should be alphanumeric "}, 400

        if not re.fullmatch(email_regex, email) or not email:
            return {"error": "Email format is invalid!"}, 400

        if Users.query.filter_by(email=request.json["email"]).first() is not None:
            return {"error": "Email already exists!"}, 409

        if Users.query.filter_by(name=request.json["name"]).first() is not None:
            return {"error": "Username already exists!"}, 409

        pwd_hash = generate_password_hash(password_hash)
        new_user = Users(
            name=username,
            email=email,
            password_hash=generate_password_hash(password_hash, method="sha256"),
        )
        Users.create(new_user)
        serializer = UserSchema()
        data = serializer.dump(new_user)

        return data, 201


class LoginUser(Resource):
    def get(self):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response(
                "Could not verify",
                401,
                {"WWW-Authenticate": 'Basic realm="Login required!"'},
            )
        user = Users.query.filter_by(name=auth.username).first()
        if not user:
            return {"message": "No user found!"}
        if check_password_hash(user.password_hash, auth.password):
            token = jwt.encode(
                {
                    "userid": user.id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                },
                app.config["SECRET_KEY"],
            )

            return {"token": token}, 200

        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )


class ForgotPassword(Resource):
    def post(self):
        if request.method == "POST":
            email = request.json["email"]
            if Users.query.filter_by(email=request.json["email"]).first() is None:
                return {"error": "Email does not exist!"}, 400

            token = s.dumps(email, salt="recovery-key")
            link = "http://localhost:5000/reset-password/"
            msg = Message(
                f"Hello from the other side!",
                sender="john.the1.mwagiru@gmail.com",
                recipients=[email],
            )
            msg.body = f"Hey, follow this {link}{token} to reset your password"
            mail.send(msg)

            return {"token": token}, 200


class ResetPassword(Resource):
    def post(self, token):
        password = request.json["password_hash"]
        try:
            email = s.loads(token, salt="recovery-key", max_age=60 * 10)
            user = Users.query.filter(Users.email == email)

            if user:
                for auser in user:
                    auser.password_hash = generate_password_hash(
                        password, method="sha256"
                    )
                    db.session.commit()
                    serializer = UserSchema()
                    data = serializer.dump(auser)
                    return data, 200
            if not user:
                return {"error": "error"}, 400
        except:
            return {"error": "no user"}, 400


class CategoryList(Resource):
    @token_required
    def get(self, current_user):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        q = request.args.get("q")
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit")
        my_categories = Categories.query.filter_by(user_id=data["userid"])
        if limit:
            try:
                limit = int(limit)
                if limit < 1:
                    return {"message": "Limit must be a positive number"}, 400
            except Exception:
                return {"message": "Check Limit Value!"}, 400
        else:
            limit = 3
        if q:
            result = [key for key in my_categories if key.name == q]
            serializer = CategorySchema(many=True)
            query = serializer.dump(result)

            return query, 200

        categories = Categories.query.filter_by(user_id=data["userid"]).paginate(
            page=page, per_page=limit
        )
        serializer = CategorySchema(many=True)
        all_categories = serializer.dump(categories)

        meta = {
            "page": categories.page,
            "pages": categories.pages,
            "total_count": categories.total,
            "prev_page": categories.prev_num,
            "next_page": categories.next_num,
            "has_next": categories.has_next,
            "has_prev": categories.has_prev,
        }

        return (all_categories, meta), 200

    @token_required
    def post(self):
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
            return (newcategory), 200

        return jsonify({"error": "category name already exists"}), 400


class CategoryAPI(Resource):
    @token_required
    def get(self, current_user, id):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        categories = Categories.query.filter(Categories.user_id == data["userid"])
        for category in categories:
            if category.id == id:
                serializer = CategorySchema()
                acategory = serializer.dump(category)
                return (acategory), 200

        return {"error": "category does not exist"}, 404

    @token_required
    def put(self, current_user, id):
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

                return (new_data), 200

        return {"error": "category does not exist"}, 404

    @token_required
    def delete(self, current_user, id):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        categories = Categories.query.filter(Categories.user_id == data["userid"])
        for category in categories:
            if category.id == id:
                Categories.delete(id)

                return {"message": "Category was successfully deleted"}, 200

        return {"error": "category was not found"}, 400


class RecipeList(Resource):
    @token_required
    def post(self, current_user):
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

            return newrecipe, 201

        return {"error": "something came up!"}, 400

    @token_required
    def get(self, current_user):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        page = request.args.get("page", 1, type=int)
        myrecipes = Recipes.query.filter_by(user_id=data["userid"])
        q = request.args.get("q")
        limit = request.args.get("limit")
        if limit:
            try:
                limit = int(limit)
                if limit < 1:
                    return {"message": "Limit must be a positive number"}, 400
            except Exception:
                return {"message": "Check Limit Value!"}, 400
        else:
            limit = 3
        if q:
            result = [key for key in myrecipes if key.name == q]
            serializer = RecipeSchema(many=True)
            query = serializer.dump(result)

            return query, 200

        recipes = Recipes.query.filter_by(user_id=data["userid"]).paginate(
            page=page, per_page=limit
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

        return (all_recipes, meta), 200


class RecipeAPI(Resource):
    @token_required
    def get(self, current_user, id):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        recipes = Recipes.query.filter(Recipes.user_id == data["userid"])
        for recipe in recipes:
            if recipe.id == id:
                serializer = RecipeSchema()
                arecipe = serializer.dump(recipe)
                return arecipe, 200

        return {"error": "recipe was not found"}, 404

    @token_required
    def put(self, current_user, id):
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

                return new_data, 200

        return {"error": "something went wrong!"}, 400

    @token_required
    def delete(self, current_user, id):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        recipes = Recipes.query.filter(Recipes.user_id == data["userid"])
        for recipe in recipes:
            if recipe.id == id:
                Recipes.delete(id)

                return {"message": "Recipe was successfully deleted"}, 200

        return {"error": "recipe was not found"}, 404


class LogoutUser(Resource):
    @token_required
    def post(self, current_user):
        token = request.headers["x-access-token"]
        invalid_token = Blacklist(revoked_token=token)
        Blacklist.save(invalid_token)

        return {"success": "successfully logged out"}, 200


api.add_resource(LoginUser, "/auth/login")
api.add_resource(RegisterUser, "/auth/register")
api.add_resource(ForgotPassword, "/auth/forgot-password")
api.add_resource(ResetPassword, "/auth/reset-password/<token>")
api.add_resource(LogoutUser, "/auth/logout")
api.add_resource(CategoryList, "/category")
api.add_resource(CategoryAPI, "/category/<int:id>")
api.add_resource(RecipeList, "/recipe")
api.add_resource(RecipeAPI, "/recipe/<int:id>")

if __name__ == "__main__":
    app.run(debug=True)
