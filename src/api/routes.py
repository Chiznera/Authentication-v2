"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

# from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

api = Blueprint('api', __name__)

# api.config["JWT_SECRET_KEY"] = "super-secret"  # Change this "super secret" with something else!
# jwt = JWTManager(app)

@api.route('/signup', methods=['POST'])
def handle_signup():
    email = request.json.get('email')
    password = request.json.get('password')
    
    if email is None:
        return jsonify(
            {'msg': 'No valid email provided.'}
        ), 400
    
    if password is None:
        return jsonify(
            {'msg': 'No valid password provided.'}
        ), 400
    check_user = User.query.filter_by(email = email).first()
   
    if check_user:
        return jsonify(
            {'msg': 'User already exist.'}
        ), 409

    user = User(email = email, password = password, is_active = True)
    db.session.add(user)
    db.session.commit()

    payload = {
        'msg': 'User creation successful.', 'user': user.serialize()
    }

    return jsonify(payload), 200


@api.route('/login', methods=['POST'])
def handle_login():
    email = request.json.get('email')
    password = request.json.get('password')
    
    user = User.query.filter_by(email = email).first()

    if user is None:
        return jsonify(
            {'msg': 'User does not exist.'}
        ), 404
    
    if password != user.password:
        return jsonify(
            {'msg': 'Incorrect password.'}
        ), 401
   


    payload = {
        'msg': 'User login successful.', 'user': user.serialize()
    }

    return jsonify(payload), 200


# @app.route("/token", methods=["POST"])
# def create_token():
#     username = request.json.get("username", None)
#     password = request.json.get("password", None)
#     # Query your database for username and password
#     user = User.query.filter_by(username=username, password=password).first()
#     if user is None:
#         # the user was not found on the database
#         return jsonify({"msg": "Bad username or password"}), 401
    
#     # create a new token with the user id inside
#     access_token = create_access_token(identity=user.id)
#     return jsonify({ "token": access_token, "user_id": user.id })