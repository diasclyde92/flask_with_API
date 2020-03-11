import os
import unittest
from app import blueprint
from flask_cors import CORS
from app.main import create_app
from flask_script import Manager
from flask_jwt_extended import JWTManager

app = create_app(os.getenv('ENV') or 'DEV')
app.register_blueprint(blueprint)
app.app_context().push()
jwt = JWTManager(app)
manager = Manager(app)
CORS(app)

if __name__ == '__main__':
    app.run()
    app.config['SOAP'] = True