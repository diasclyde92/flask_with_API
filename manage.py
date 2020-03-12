import os
import unittest
from app import blueprint
from flask_cors import CORS
from app.main import create_app
from flask_script import Manager
from flask_jwt_extended import JWTManager
from flask import render_template
from app.main.service.constants import *

app = create_app(os.getenv('ENV') or 'DEV')
app.register_blueprint(blueprint)
app.app_context().push()
jwt = JWTManager(app)
manager = Manager(app)
CORS(app)

@app.route('/register/')
def navigationMenu():
   gender_array = [{'male':Const.MALE,'female':Const.FEMALE}]
   empty_message = [Const.EMPTY_MESSAGE]
   passwords_do_not_match = Const.PASSWORDS_DO_NOT_MATCH
   return render_template("register.html",gender_array=gender_array,empty_message=empty_message,passwords_do_not_match=passwords_do_not_match)

@app.route('/login/')
def login():
   return render_template("login.html")


if __name__ == '__main__':
    app.run()
    app.config['SOAP'] = True