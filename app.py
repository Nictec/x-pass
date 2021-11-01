import os

from flask import Flask, jsonify, request, session
from flask_session import Session

from yaml import safe_load
from models import *
from encryption.manager import Manager
from helpers.lists import serialize_list
from nacl.exceptions import CryptoError

# parse the config
with open("config.yml") as f:
    config = safe_load(f)

# set up flask
app = Flask("__name__")
app.config["TORTOISE_ORM_DATABASE_URI"] = config.get("database_uri")
app.config['TORTOISE_ORM_MODELS'] = "models"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_NAME"] = "xvault_session"
app.config['SECRET_KEY'] = os.urandom(12).hex()

# set up the session
Session(app)


# set up the encryption manager
encryption = Manager()

# controllers
@app.get("/")
async def index():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(f"{rule}")

    return jsonify(routes)

# TODO: add role restrictions to all admin routes
@app.post("/admin/users/create")
async def add_user():
    post_data = request.get_json()
    user_crypt = encryption.prepare_user(post_data.get("password"))
    user = await User.create(username=post_data.get("username"),
                             encrypted_privkey=user_crypt.get("encrypted_priv_key"),
                             public_key=user_crypt.get("public_key"),
                             salt=user_crypt.get("salt")
                             )
    return jsonify(user.serialize())

@app.get("/admin/users")
async def get_users():
    users = await User.all()
    return jsonify(serialize_list(users))

@app.post("/login")
async def login():
    username = request.get_json().get("username")
    password = request.get_json().get("password")

    user = await User.get(username=username)

    try:
        privkey = encryption.decrypt_private_key(user.encrypted_privkey, user.salt, password)
        session["privkey"] = privkey
    except CryptoError:
        return {"status":"Error", "message": "username or password wrong"}


    return {"status": "OK", "message": "logged in successfully"}




if __name__ == "__main__":
    # init the db
    db.init_app(app)
    db.generate_schemas()
    app.run(debug=True)
