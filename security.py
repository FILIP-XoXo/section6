from werkzeug.security import safe_str_cmp #bezpecne porovnanie stringov
from models.user import UserModel



def authenticate(username, password):
    user = UserModel.find_by_username(username)
    #vraciame user objekt za pouzitia mappingu
    #default value None, ak ho nenajdeme
    if user and safe_str_cmp(user.password, password):
        #porovnavame user password s heslom ziskaneho z mappingu
        return user
        #ak sa zhoduju - vraciame User-a a generujeme JWT token


def identity(payload):
    # pri poziadavke endpointu ktory vyzaduje autetifikaciu vyzivame identity method
    user_id = payload['identity']
    # za predpokladu ze sa dostaneme User-ovo ID predpokaldame ze JWT token bol spravny
    return UserModel.find_by_id(user_id)
