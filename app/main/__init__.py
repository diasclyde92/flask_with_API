from flask import Flask
from flask_restplus import Api
from flask_mongoengine import MongoEngine
from flask_bcrypt import Bcrypt
from .config import config_by_name

mdb = MongoEngine()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
bcrypt = Bcrypt(app)


def create_app(config_name):
    app = Flask(__name__,template_folder="views",)
    app.config.from_object(config_by_name[config_name])
    #Below we have changed the setting to upload file size to 25 MB
    app.config['MAX_CONTENT_LENGTH'] = 25*1024*1024
    db = MongoEngine()

    with app.app_context():
        db.init_app(app)
        bcrypt.init_app(app)

    return app