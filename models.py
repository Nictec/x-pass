from flask_tortoise import Tortoise, Model, fields

db:"Tortoise" = Tortoise()

class User(db.Model):
    id = db.IntField(pk=True)
    username = db.CharField(max_length=50)
    encrypted_privkey = db.BinaryField()
    public_key = db.BinaryField()
    salt = db.BinaryField()

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username
        }
