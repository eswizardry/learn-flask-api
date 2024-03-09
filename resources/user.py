from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, get_jwt, jwt_required
from passlib.hash import pbkdf2_sha256

from blocklist import BLOCKLIST

from schemas import UserSchema
from models import UserModel

from db import db

blp = Blueprint("Users", __name__, description="Operation on users")

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    @blp.response(201, UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter_by(username=user_data["username"]).first()
        if user:
            abort(400, message="User already exists.")

        user = UserModel(**user_data)
        user.password = pbkdf2_sha256.hash(user.password)

        db.session.add(user)
        db.session.commit()

        return user

@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema(only=["username", "password"]))
    def post(self, user_data):
        user = UserModel.query.filter_by(username=user_data["username"]).first()
        if not user or not pbkdf2_sha256.verify(user_data["password"], user.password):
            abort(401, message="Invalid username or password.")

        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)
        return {"access_token": access_token, "refresh_token": refresh_token}

@blp.route("/refresh")
class UserRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": access_token}
    
@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out."}

@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}

    @blp.arguments(UserSchema)
    @blp.response(200, UserSchema)
    def put(self, user_data, user_id):
        user = UserModel.query.get(user_id)
        if user:
            user.username = user_data["username"]
            user.password = user_data["password"]
        else:
            user = UserModel(id=user_id, **user_data)

        db.session.add(user)
        db.session.commit()

        return user
