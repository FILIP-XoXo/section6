from db import db

class StoreModel(db.Model):
    __tablename__ = 'stores'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))

    #MANY TO ONE relationship
    items = db.relationship('ItemModel' , lazy='dynamic')
    # list of ItemModel
    # lazy=dynamic zabezpecuje ze do bodu pokial nevolame fuknciu "json",
    # nenahliadame do tabulky


    # moze byt bez dynamic a .all nemubde tiez

    def __init__(self, name):
        self.name = name


    def json(self):
        return {'name': self.name, 'items': [item.json() for item in self.items.all()]}

        #SPRAVNA
        #return [item.json() for item in self.items.all()]
        # diktionary

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
