from flask_restplus import Namespace, fields
from app.main.service.constants import TimeFormat

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}


class UsersDto:
    api = Namespace('users', authorizations=authorizations, description='User types related operations')

    Name = api.model('Name', {
        'firstName': fields.String(),
        'lastName': fields.String(),
    })

    UsersPost = api.model('UsersPost', {
        'username': fields.String(),
        'password': fields.String(),
        'name': fields.Nested(Name),
        'profile_image': fields.String(),
        'deleted': fields.Boolean(),
        'date_of_birth': fields.DateTime(),
        'gender': fields.String(),
        'email': fields.String(),
        'contact': fields.String(),
    })

    UsersGet = api.model('UsersGet', {
        'publicId': fields.String(),
        'username': fields.String()
    })

    UsersPut = api.model('UsersPut', {
        'publicId': fields.String(),
        'username': fields.String(),
        'password': fields.String(),
        'name': fields.Nested(Name),
        'profile_image': fields.String(),
        'deleted': fields.Boolean(),
        'date_of_birth': fields.DateTime(),
        'gender': fields.String(),
        'email': fields.String(),
        'contact': fields.String(),
    })

    UsersDelete = api.model('UsersDelete', {
        'publicId': fields.String()
    })

    UserCheckDuplicateUsername = api.model('UserCheckDuplicateUsername', {
        'username': fields.String(),
    })

