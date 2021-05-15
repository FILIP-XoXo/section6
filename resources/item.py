from flask_restful import Resource, reqparse
from flask_jwt import jwt_required
from models.item import ItemModel

class Item(Resource):
    # parser oznacuje argumenty, ktore pre uspesnu poziadavku na server
    # musi obsahovat JSON BODY
    # ine zadane argumenty nebudu zahrnute v JSON payload
    parser = reqparse.RequestParser()
    parser.add_argument('price',
        type=float,
        required=True,
        help="This field cannot be left blank"
    )
    parser.add_argument('store_id',
        type=int,
        required=True,
        help="Every item needs a store id"
    )

    @jwt_required()
    def get(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item not found'}, 404
        # 400 bad request - pozadovany item sa nenasiel



    def post(self, name):
        if ItemModel.find_by_name(name): #self namiesto Item
            return {'message': "an item with name '{}' already exists".format(name)}, 400

        data = Item.parser.parse_args()
        #kontrola argumentov

        item = ItemModel(name, data['price'], data['store_id'])
        # item = {'name': name, 'price': data['price']}
        #diktionary
        try:
            item.save_to_db()
        except:
            return {"message": "An error occurred inserting item."}, 500
            # 500 internal server error, chyba na strane servera
        return item.json(), 201 #JSON


    def delete(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()

        return {'message': 'Item deleted'}

        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()
        #
        # query = "DELETE FROM items WHERE name=?"
        # cursor.execute(query, (name,))
        #
        # connection.commit()
        # connection.close()
        #
        # return {'message': 'Item deleted'}


    #update ak sa cena zmenila alebo insert NEW ONE
    def put(self, name):
        data = Item.parser.parse_args()

        item = ItemModel.find_by_name(name)
        # najdenie itemu v databaze

        if item is None:
            item = ItemModel(name, data['price'], data['store_id'])
            # ak funkcia find_by_name nenasla pozadovany item, vytvorime novy
        else:
            item.price = data['price']

        item.save_to_db()

        return item.json()



class ItemList(Resource):
    def get(self):
        return [x.json() for x in ItemModel.query.all()]
        #return {'items': [x.json() for x in ItemModel.query.all()]}

        # vrati vsetky data v databaze


        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()
        #
        # query = "SELECT * FROM items"
        # result = cursor.execute(query)
        # items = []
        # for row in result:
        #     items.append({'name': row[0], 'price': row[1]})
        #
        # connection.close()
        #
        # return {'items': items}
