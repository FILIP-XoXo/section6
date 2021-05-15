import sqlite3
from flask_restful import Resource, reqparse
from models.user import UserModel

class UserRegister(Resource):

    parser = reqparse.RequestParser()
    #parser skontroluje ci BODY JSON requestu obsahuje argumenty
    parser.add_argument('username',
        type=str,
        required=True,
        help="This field cannot be blank"
    )
    parser.add_argument('password',
        type=str,
        required=True,
        help="This field cannot be blank"
    )

    def post(self):
        data = UserRegister.parser.parse_args()

        if UserModel.find_by_username(data['username']):
            #ak username zadane JSON requeste uz existuje, poziadavka skonci s prislusnou spravou
            return {"message": "A user with that username is already taken"}, 400

        user = UserModel(data['username'], data['password']) #(**data)
        user.save_to_db()
        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()
        #
        # query = "INSERT INTO users VALUES (NULL, ?, ?)"
        # #NULL pretoze ID mame AUTO-INCREMENT
        # cursor.execute(query, (data['username'], data['password']))
        #
        # connection.commit()
        # connection.close()

        return {"message": "User created successfully."}, 201
