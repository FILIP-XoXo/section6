import os
import re

from flask import Flask, request, jsonify, make_response
from flask_restful import Api
import uuid #generate random puclic id
from werkzeug.security import generate_password_hash, check_password_hash
#password hashing function, v dabaze budu zahashovane
import jwt
import datetime
from functools import wraps
from flask_jwt import JWT

from security import authenticate, identity

from resources.user import UserRegister
from resources.item import Item, ItemList
from resources.store import Store,StoreList

app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1)

#uri = os.getenv("DATABASE_URL")
uri = os.getenv("DATABASE_URL")  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

#  Heroku Postgres services vyuzivajuca SQLAlchemy >= 1.4.x
# rest of connection code using the connection string `uri`
app.config['SQLALCHEMY_DATABASE_URI'] = uri


# DATABASE_URL predstavuje premennu(variable), ktoru pre nas vytvoril Heroku
# fukcia vyziada v operacnom systeme - environment variable
# prvy parameter predstavuje premennu, s prioritou prveho citania, v pripade ak
# premenna DATABASE_URL sa nenachadza v systeme(pretoze nie je nastavena), vyuzijeme defaultnu hodnotu,
# ktoru zastupuje druhy parameter ako SQLite databaza urcena na lokalne testovanie
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# v pripade ak objekt bol zmeneny ale neulozeny do databazy,
# extension SQLALCHEMY sleduje každú zmenu, ktora nastane v SQL ALCHEMY session
# funkciu vypiname pretoze SQL ALCHEMY samotna kniznica dospinuje vlastnou
# modifikaciou tracker-u (sledovania)
# neznemoznuje SQL ALCHEMY spravanie, iba rozsirenie
app.secret_key = 'longcomplicatedsecuritykey'
api = Api(app)

# vytvorenie vsetkych tabuliek do suboru data.db pred vykonanim prveho requestu
jwt = JWT(app, authenticate, identity)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    __tablename__ = 'todos'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# LOGIN ------------------------------------------------------------
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8'), 'public_id' : user.public_id})

    return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})
# LOGIN ------------------------------------------------------------

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'cannot perform function'})
        #admin is false, iba admini mozu vykonavat tieto funkcie

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify(output)


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify(user_data)

@app.route('/user', methods=['POST'])
#@token_required
#def create_user(current_user):
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'new user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': ' user promoted'})

#---------------------------------------------------------------------------
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': ' user deleted'})

#---------------------------------------------------------------------------

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify(output)

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'no todo found'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify(todo_data)

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'TODO created'})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'no todo found'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message': 'Todo item completed'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    return ''

api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')

api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')

# pri spusteni python suboru, python prideli vzdy danemu suboru nazov __main__
# ostatne subory z ktorych su importovane metody,triedy su oznacene inak
# pri importe z app.py tak zabranime jeho spusteniu
if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
