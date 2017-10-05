"""
import os
from app import create_app

config_name = os.getenv('APP_SETTINGS') # config_name = "development"
app = create_app(config_name)

if __name__ == '__main__':
    app.run()
"""
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'alvintaremwa'
app.config['SQLALCHEMY_DATABASE_URI'] ="postgresql://postgres:123@localhost:5432/recipeAPI_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    #user attributes
    name = db.Column(db.String(50))
    email = db.Column(db.String(80))
    password = db.Column(db.String(80))
    #to check for administartor rights
    admin = db.Column(db.Boolean)

class recipes(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     text =db.Column(db.String(50))
     complete = db.Column(db.Boolean)
     user_id = db.Column(db.Integer)

def token_needed(d):
    @wraps(d)
    def decorated(*args,**kwargs):
        token =None
        if 'x-header-token' in request.headers:
            token = request.headers['x-header-token']
        if not token:
            return jsonify({'message':'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            present_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify ({'message':'Token is invalid'}), 401

        return d(present_user, *args, **kwargs)
    return decorated


@app.route('/login')
#@token_needed
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify--No info given', 401, {'WWW-Authenticate':'Basic realm="login required"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify--User doesnot exist', 401, {'WWW-Authenticate':'Basic realm="Login required!!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})
    return make_response('Could no verify--Password incorrect ', 401, {'WWW-Authenticate':'basic realm="Login required!!!!"'})

@app.route('/user', methods=['GET'])
@token_needed
def get_users_in_db(present_user):
    """
    if not present_user.admin:
        return jsonify ({'message':'Cannot perform that function!!'})
    """
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['email'] = user.email
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET']) #using public in place of user_id
@token_needed
def get_singleuser(present_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
#@token_needed
def create_user():
    data = request.get_json()
    print(data,"qwerty")
    hash_password = generate_password_hash(data['password'], method = 'sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'],email=data['email'], password=hash_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify ({'message':'New User created'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_needed
def push_user(present_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})
    user.admin = True
    db.session.commit()
    return jsonify ({'message':'user has been promoted to administrator'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_needed
def delete_user(present_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'user has been deleted'})

#recipe routes

@app.route('/recipe', methods=['GET'])
@token_needed
def get_all_recipes(present_user):
    recipe = recipes.query.filter_by(user_id=present_user.id).all()
    output = []
    for recipez in recipe:
        recipe_data = {}
        recipe_data['id'] = recipez.id
        recipe_data['text'] = recipez.text
        recipe_data['complete'] = recipez.complete
        # recipe_data['Item List'] = recipez.itemList
        # recipe_data['id'] = todo.id
        output.append(recipe_data)
    return jsonify({'recipes':output})

@app.route('/recipe/recipe_id', methods=['GET'])
@token_needed
def get_singlerecipe(present_user, recipe_id):
    recipez = recipes.query.filter_by(id=recipe_id, user_id=present_user.id).first()
    if not recipez:
        return jsonify({'message':'No recipe found!'})

    recipe_data = {}
    recipe_data['id'] = recipez.id
    recipe_data['text'] = recipez.text
    recipe_data['complete'] = recipez.complete
    # recipe_data['Item List'] = recipe.itemList
    return jsonify(recipe_data)

@app.route('/recipe', methods=['POST'])
@token_needed
def create_recipes(present_user):
    data = request.get_json()
    newrecipe = recipes(text=data['text'], complete=False, user_id=present_user.id)
    db.session.add(newrecipe)
    db.session.commit()

    return jsonify({'message':"Recipe created"})

@app.route('/recipe/<recipe_id>', methods=['PUT'])
@token_needed
def update_recipes(present_user, recipe_id):
    recipez = recipes.query.filter_by(id=recipe_id, user_id=present_user.id).first()
    if not recipez:
        return jsonify({'message':'No recipe found!'})

    recipez.complete = True
    db.session.commit()

    return jsonify({'message':'recipe created!!!'})

@app.route('/recipe/recipe_id', methods=['DELETE'])
@token_needed
def delete_recipes(present_user, recipe_id):
    recipez = recipes.query.filter_by(id=recipe_id, user_id=present_user.id).first()
    if not recipez:
        return jsonify({'message':'No recipe found!'})
    db.session.delete(recipez)
    db.session.commit()

    return jsonify({'message':'Recipe deleted'})

if __name__=='__main__':
    app.run(debug=True)
