"""
* Name: users_controller.py
* Description : All User types API's
* Author: www.opspl.com
* Date Created: 2nd Dec 2019
* Date Modified: 2nd Dec 2019
*
"""

from ..service.users_service import insert_users, fetch_users, update_users, \
                                           delete_users,check_duplicate_username

from ..util.users_dto import UsersDto
from app.main.service.constants import *
from flask_restplus import Resource
from flask import request

# parser.add_argument('per_page', type=int, required=False, choices=[5, 10, 20, 30, 40, 50])

api = UsersDto.api

_insert_users = UsersDto.UsersPost
_fetch_users = UsersDto.UsersGet
_update_users = UsersDto.UsersPut
_delete_users = UsersDto.UsersDelete
_check_duplicate_username = UsersDto.UserCheckDuplicateUsername

@api.route('/')
class Users(Resource):
    @api.expect(_insert_users, validate=True)
    #@api.doc(security='apikey')
    #@roles_required(Const.SITE_ADMIN, 'STUDENT')
    def post(self):
        """Create a new User"""
        data = request.json
        return insert_users(data=data)

    @api.expect(_update_users, validate=True)
    def put(self):
        """Update User"""
        data = request.json
        return update_users(data=data)

    @api.marshal_list_with(_fetch_users, envelope='data')
    @api.expect(Const.parser, validate=True)
    def get(self):
        """List all Users"""
        try:
            args = Const.parser.parse_args()
        except Exception as e:
            args = request.args
        return fetch_users(data=args)

    @api.expect(_delete_users, validate=True)
    def delete(self):
        """Delete User"""
        data = request.json
        return delete_users(data=data)

@api.route('/check-duplicate-username/')
class checkDupUsername(Resource):
    @api.expect(_check_duplicate_username, envelope='data')
    def post(self):
        data = request.json
        """Check For Order Number"""
        return check_duplicate_username(data=data)