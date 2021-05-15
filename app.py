import os
import re

from flask import Flask
from flask_restful import Api
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
#jwt vytvori novy endpoint /auth (pri volani endpointu posielame username a password)
#jwt ich posle do authenticate function
#po uspesnom porovnani dostaneme jwt token, ktory vieme poslat v nadchadzajucom requeste

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
