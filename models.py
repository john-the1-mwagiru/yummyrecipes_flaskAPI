from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from marshmallow import Schema, fields
import datetime

db = SQLAlchemy()


class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(32), index=True)
    name = db.Column(db.String(32))
    password_hash = db.Column(db.String(128))
    recipes = db.relationship("Recipes", backref="users", cascade="all, delete-orphan")
    categories = db.relationship(
        "Categories", backref="users", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return "<User(email='%s',password_hash='%s',name= '%s')>" % (
            self.email,
            self.password_hash,
            self.name,
        )

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def create(cls, data):
        new_user = data
        db.session.add(new_user)
        db.session.commit()
        
        return new_user

    @classmethod
    def edit(cls, id, data):
        user = Users.get(id)
        user.email = data.email
        user.password_hash = data.password_hash
        user.name = data.name
        db.session.commit()
        
        return user

    @classmethod
    def delete(cls, id):
        user = Users.get(id)
        del user

        return jsonify({"message": "Deleted"}), 204


class UserSchema(Schema):
    id = fields.Integer()
    email = fields.String()
    name = fields.String()
    password_hash = fields.String()


class Categories(db.Model):
    __tablename__ = "categories"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    description = db.Column(db.String(32))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    recipes = db.relationship(
        "Recipes", backref="categories", cascade="all, delete-orphan"
    )
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(
        db.DateTime,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )

    def __repr__(self):
        return (
            "<User(name='%s',description='%s',user_id= '%d',date_created ='%s',date_modified='%s')>"
            % (
                self.name,
                self.description,
                self.user_id,
                self.date_created,
                self.date_modified,
            )
        )

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def create(cls, data):
        new_category = data
        db.session.add(new_category)
        db.session.commit()
        
        return new_category

    @classmethod
    def edit(cls, id, data):
        category = Categories.get(id)
        category.name = data.name
        category.description = data.description
        db.session.commit()

        return category

    @classmethod
    def delete(cls, id):
        category = Categories.get(id)
        db.session.delete(category)
        db.session.commit()

        return jsonify({"message": "category deleted!"})


class CategorySchema(Schema):
    id = fields.Integer()
    name = fields.String()
    description = fields.String()
    user_id = fields.String()
    date_created = fields.String()
    date_modified = fields.String()


class Recipes(db.Model):
    __tablename__ = "recipes"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    ingredients = db.Column(db.String(400))
    directions = db.Column(db.String(400))
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(
        db.DateTime,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )

    def __repr__(self):
        return (
            "<User(name='%s',ingredients='%s',directions= '%s',category_id='%d',user_id='%d',date_created='%s', date_modified ='%s')>"
            % (
                self.name,
                self.ingredients,
                self.directions,
                self.category_id,
                self.user_id,
                self.date_created,
                self.date_modified,
            )
        )

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def create(cls, data):
        new_recipe = data
        db.session.add(new_recipe)
        db.session.commit()

        return new_recipe

    @classmethod
    def edit(cls, id, data):
        recipe = Recipes.get(id)
        recipe.name = data.name
        recipe.ingredients = data.ingredients
        recipe.directions = data.directions
        db.session.commit()

        return recipe

    @classmethod
    def delete(cls, id):
        recipe = Recipes.get(id)
        db.session.delete(recipe)
        db.session.commit()

        return jsonify({"message": "recipe deleted!"})


class RecipeSchema(Schema):
    id = fields.Integer()
    name = fields.String()
    ingredients = fields.String()
    directions = fields.String()
    category_id = fields.Integer()
    user_id = fields.Integer()
    date_created = fields.String()
    date_modified = fields.String()


class Blacklist(db.Model):
    __tablename__ = "blocklist"

    token_id = db.Column(db.Integer, unique=True, primary_key=True)
    revoked_token = db.Column(db.String(500), nullable=True)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return "<Revoked token: {}".format(self.revoked_token)
