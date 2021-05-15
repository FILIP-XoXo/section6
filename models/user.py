import sqlite3
from db import db

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True) #auto-increment
    username = db.Column(db.String(80))
    password = db.Column(db.String(80))


    def __init__(self, username, password):
        self.username = username
        self.password = password


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()



    #metody find_by_username a find_by_id predstavuju Application Programming Interface,
    #ktore vyuziva subor security.py pre komunikaciu s pouzivatelom (User) a databazou

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
        # SELECT * FROM users

        #cls reprezentuje pouzitie triedy User
        #self - potrebuje kazda metoda pre interakciu s python objektom
        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()
        #
        # query = "SELECT * FROM users WHERE username=?"
        # result = cursor.execute(query, (username,))
        # # parametre vo formate "tuple", ktory vytvarame
        # row = result.fetchone()
        # if row is not None:
        #     user = cls(row[0], row[1], row[2]) #cls = User(*row)
        # else:
        #     user = None
        #
        # connection.close()
        # return user

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()
        #cls reprezentuje pouzitie triedy User
        #self - potrebuje kazda metoda pre interakciu s python objektom
        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()
        #
        # query = "SELECT * FROM users WHERE id=?"
        # result = cursor.execute(query, (_id,))
        # # parametre vo formate "tuple", ktory vytvarame
        # row = result.fetchone()
        # if row is not None:
        #     user = cls(row[0], row[1], row[2]) #cls = User(*row)
        # else:
        #     user = None
        #
        # connection.close()
        # return user
