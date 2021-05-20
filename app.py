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

from db import db


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



class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(240), unique=True)
    name = db.Column(db.String(240))    # prihlasovaci udaj
    password = db.Column(db.Text)       # prihlasovaci udaj
    admin = db.Column(db.Boolean)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    mail = db.Column(db.String(50))
    phone_number = db.Column(db.String(15))
    street = db.Column(db.String(20))
    city = db.Column(db.String(20))
    zip = db.Column(db.String(5))
    weight = db.Column(db.Integer)
    height = db.Column(db.Integer)
    born_data = db.Column(db.String(30))
    rodne_cislo = db.Column(db.String(12))
    insurance_number = db.Column(db.Integer)

class Doctor(db.Model):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(240), unique=True)
    name = db.Column(db.String(240))
    password = db.Column(db.Text)
    admin = db.Column(db.Boolean)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    mail = db.Column(db.String(50))
    phone_number = db.Column(db.String(15))
    specification = db.Column(db.String(100))

class Meranie_tlak(db.Model):
    __tablename__ = 'meranie_tlakov'
    id = db.Column(db.Integer, primary_key=True)
    sys = db.Column(db.Integer)
    dia = db.Column(db.Integer)
    street = db.Column(db.String(20)) # udaje ziskane z GPS mobilu
    city = db.Column(db.String(20))
    #user_id = db.Column(db.Integer)
    datum = db.Column(db.String(50))
    vaznost = db.Column(db.Integer) # 1/2/3 3 predsatavuje rizikovu hodnotu
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    mail = db.Column(db.String(50))
    phone_number = db.Column(db.String(15))



class Meranie_pulz(db.Model):
    __tablename__ = 'meranie_pulzov'
    id = db.Column(db.Integer, primary_key=True)
    pulse = db.Column(db.Integer)
    street = db.Column(db.String(20)) # udaje ziskane z GPS mobilu
    city = db.Column(db.String(20))
    #user_id = db.Column(db.Integer)
    datum = db.Column(db.String(50))
    vaznost = db.Column(db.Integer) # 1/2/3 3 predsatavuje rizikovu hodnotu
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    mail = db.Column(db.String(50))
    phone_number = db.Column(db.String(15))

class Meranie_teplota(db.Model):
    __tablename__ = 'meranie_teplot'
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.Integer)
    room_temperature = db.Column(db.Integer)
    street = db.Column(db.String(20)) # udaje ziskane z GPS mobilu
    city = db.Column(db.String(20))
    #user_id = db.Column(db.Integer)
    datum = db.Column(db.String(50))
    vaznost = db.Column(db.Integer) # 1/2/3 3 predsatavuje rizikovu hodnotu
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    mail = db.Column(db.String(50))
    phone_number = db.Column(db.String(15))



# TOKENY ------------------------------------------------------------------------------

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
            current_user = Patient.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


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
            current_user = Doctor.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# TOKENY -------------------------------------------------------------------



# LOGIN ------------------------------------------------------------
@app.route('/login/patient')
def login_patient():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    pouzivatel = Patient.query.filter_by(name=auth.username).first()

    if not pouzivatel:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    if check_password_hash(pouzivatel.password, auth.password):
        token = jwt.encode({'public_id': pouzivatel.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=900)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8'), 'public_id' : pouzivatel.public_id})

    return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})


@app.route('/login/doctor')
def login_doctor():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    pouzivatel = Doctor.query.filter_by(name=auth.username).first()

    if not pouzivatel:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

    if check_password_hash(pouzivatel.password, auth.password):
        token = jwt.encode({'public_id': pouzivatel.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=900)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8'), 'public_id' : pouzivatel.public_id})

    return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})
# LOGIN ------------------------------------------------------------


# PATIENT
@app.route('/patient', methods=['POST'])
def create_patient():
    data = request.get_json()

    pacient = Patient.query.filter_by(name=data['name']).first()
    if pacient:
        #ak username zadane JSON requeste uz existuje, poziadavka skonci s prislusnou spravou
        return {"message": "A user with that username is already taken"}, 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_patient = Patient(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False,first_name=data['first_name'],
    last_name=data['last_name'],mail=data['mail'],phone_number=data['phone_number'],street=data['street'],
    city=data['city'],
    zip=data['zip'],
    weight=data['weight'],
    height=data['height'],
    born_data=data['born_data'],
    rodne_cislo=data['rodne_cislo'],
    insurance_number=data['insurance_number']
    )
    db.session.add(new_patient)
    db.session.commit()

    return jsonify({'message': 'new patient created'})

# DOKTOR
@app.route('/doctor', methods=['POST'])
def create_doctor():
    data = request.get_json()

    doktor = Doctor.query.filter_by(name=data['name']).first()
    if doktor:
        #ak username zadane JSON requeste uz existuje, poziadavka skonci s prislusnou spravou
        return {"message": "A user with that username is already taken"}, 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_doctor = Doctor(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=True,first_name=data['first_name'],
    last_name=data['last_name'],mail=data['mail'],phone_number=data['phone_number'],specification=data['specification']
    )
    db.session.add(new_doctor)
    db.session.commit()

    return jsonify({'message': 'new doctor created'})



# MERANIE TLAKU -------------------------------------------------------------------------------------------------
@app.route('/meranie_tlak/<meno>', methods=['POST'])
@token_required
def meranie_tlaku_create(current_user, meno):
    data = request.get_json()

    pouzivatel = Patient.query.filter_by(name=meno).first()

    meranie = Meranie_tlak(
        sys=data['sys'],
        dia=data['dia'],
        street=data['street'],
        city=data['city'],
        datum=data['datum'],
        vaznost=data['vaznost'],
        first_name=pouzivatel.first_name,
        last_name=pouzivatel.last_name,
        mail=pouzivatel.mail,
        phone_number=pouzivatel.phone_number
    )

    db.session.add(meranie)
    db.session.commit()

    return jsonify({'message': 'Meraniu tlaku - created'})

# MERANIE PULZU -------------------------------------------------------------------------------------------------
@app.route('/meranie_pulz/<meno>', methods=['POST'])
@token_required
def meranie_pulzu_create(current_user):
    data = request.get_json()

    pouzivatel = Patient.query.filter_by(name=meno).first()

    meranie = Meranie_pulz(
        pulse=data['pulse'],
        street=data['street'],
        city=data['city'],
        datum=data['datum'],
        vaznost=data['vaznost'],
        first_name=pouzivatel.first_name,
        last_name=pouzivatel.last_name,
        mail=pouzivatel.mail,
        phone_number=pouzivatel.phone_number
        )
    db.session.add(meranie)
    db.session.commit()

    return jsonify({'message': 'Meranie pulzu created'})

# MERANIE TEPLOTY -------------------------------------------------------------------------------------------------
@app.route('/meranie_teplota/<meno>', methods=['POST'])
@token_required
def meranie_teploty_create(current_user):
    data = request.get_json()

    pouzivatel = Patient.query.filter_by(name=meno).first()

    meranie = Meranie_teplota(
        temperature=data['temperature'],
        room_temperature=data['room_temperature'],
        street=data['street'],
        city=data['city'],
        datum=data['datum'],
        vaznost=data['vaznost'],
        first_name=pouzivatel.first_name,
        last_name=pouzivatel.last_name,
        mail=pouzivatel.mail,
        phone_number=pouzivatel.phone_number
        )
    db.session.add(meranie)
    db.session.commit()

    return jsonify({'message': 'Meranie teploty created'})


# ------------------------------------- KONIEC VKLANIE ZAZNAMOV ----------------------

@app.route('/meranie_tlak/den/<datum>', methods=['GET'])
@token_required
def get_all_meranie_tlak(current_user, datum):


    vysledky = Meranie_tlak.query.filter_by(datum=datum).all()

    output = []

    for x in vysledky:
        data = {}
        data['sys']=x.sys,
        data['dia']=x.dia,
        data['street']=x.street,
        data['city']=x.city,
        data['vaznost']=x.vaznost,
        data['first_name']=x.first_name,
        data['last_name']=x.last_name,
        data['mail']=x.mail,
        data['phone_number']=x.phone_number
        data['datum']=x.datum
        output.append(data)

    return jsonify(output)

@app.route('/meranie_pulz/den/<datum>', methods=['GET'])
@token_required
def get_all_meranie_pulz(current_user, datum):

    vysledky = Meranie_pulz.query.filter_by(datum=datum).all()

    output = []

    for x in vysledky:
        data = {}
        data['pulse']=x.pulse,
        data['street']=x.street,
        data['city']=x.city,
        data['vaznost']=x.vaznost,
        data['first_name']=x.first_name,
        data['last_name']=x.last_name,
        data['mail']=x.mail,
        data['phone_number']=x.phone_number
        data['datum']=x.datum
        output.append(data)

    return jsonify(output)



@app.route('/meranie_teplota/den/<datum>', methods=['GET'])
@token_required
def get_all_meranie_teplota(current_user, datum):

    vysledky = Meranie_teplota.query.filter_by(datum=datum).all()

    output = []

    for x in vysledky:
        data = {}
        data['temperature']=x.temperature,
        data['room_temperature']=x.room_temperature,
        data['street']=x.street,
        data['city']=x.city,
        data['vaznost']=x.vaznost,
        data['first_name']=x.first_name,
        data['last_name']=x.last_name,
        data['mail']=x.mail,
        data['phone_number']=x.phone_number
        data['datum']=x.datum
        output.append(data)

    return jsonify(output)



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



# pri spusteni python suboru, python prideli vzdy danemu suboru nazov __main__
# ostatne subory z ktorych su importovane metody,triedy su oznacene inak
# pri importe z app.py tak zabranime jeho spusteniu
if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
