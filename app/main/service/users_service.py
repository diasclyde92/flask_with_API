"""
* Name: users_service.py
* Description : All User types related functions
* Author: www.opspl.com
* Date Created: 2nd Dec 2019
* Date Modified: 2nd Dec 2019
*
"""

from app.main.model.users import Users
import uuid
from app.main.service.constants import *
from app.main import bcrypt

def gen_salt():
    salt = str(os.urandom(random.randint(14, 18))).lstrip('b')
    return salt


def hash_password(passwordString, salt):
    hhash = bcrypt.generate_password_hash(salt + passwordString)
    return hhash

def insert_users(data):
    try:
        salt = gen_salt()
        data['password'] = hash_password(data['password'], salt)
        data['publicId'] = uuid.uuid4()
        try:
            Users(**data).save()
        except Exception as e:
            print(e)
        response_object = {
            'status': "Success",
            'statusCode': 200,
            'message': 200
        }
        return response_object, 201
    except Exception as e:
        response_object = {
            'status': "Fail",
            'statusCode': 400,
            'message': "message"
        }
        return response_object , 400


def update_users(data):
    try:
        Users.objects(publicId=data['publicId']).update(**data)
        response_object = {
            'status': "Success",
            'statusCode': 200,
            'message': 200
        }
        return response_object, 201

    except Exception as e:
        response_object = {
            'status': "Fail",
            'statusCode': 400,
            'message': "message"
        }
        return response_object


def fetch_users(data):
    conditions = {"status": "ACTIVE"}
    #Below specified are the fields from 'trainings' collection to be fetched
    project_data = {"$project":
        {
            'publicId': 1,
            'trainingType': 1,
            'name': 1,
            'description': 1,
            'status': 1,
            'price': 1,
            'sectionDescription': 1
        }
    }
    if data['publicId'] is not None:
        conditions['publicId'] = uuid.UUID(data['publicId'])
        try:
            dataset = Users.objects.aggregate(*[
                {"$match": conditions},
                project_data
            ])
            details = list(dataset)
            return details
        except Exception as e:
            response_object = {
                'status': Const.FAIL,
                'message': e,
                'statusCode': Const.FAILURE_CODE
            }
            return response_object

    else:
        query_data = []
        query_data.append({"$match": conditions})
        #The below if part fetches the data based on parameters passed
        if data['page'] is not None:
            query_data.append({"$limit": (int(int(data['page']) * int(data['per_page'])))})
            query_data.append({"$skip": (int(int(data['page'] - 1) * int(data['per_page'])))})
        #The below else part fetches the data with default limit value if parameters are not passed
        else:
            query_data.append({"$limit": (int(100))})
            query_data.append({"$skip": (int(0))})

        query_data.append(project_data)
        dataset = Users.objects.aggregate(*query_data)
        details = list(dataset)
    return details


def delete_users(data):
    try:
        Users.objects(publicId=data['publicId']).delete()
        response_object = {
            'status': "Success",
            'statusCode': 200,
            'message': 200
        }
        return response_object
    except Exception as e:
        response_object = {
            'status': "Fail",
            'statusCode': 400,
            'message': "message"
        }
        return response_object

def check_duplicate_username(data):
    conditions = {"username": {"$regex": "^"+str(data['username'])+"$", "$options": "i"} }
    try:
        dataset = Users.objects.aggregate(*[
            {"$match": conditions},
            {"$project":
                {
                    "username": 1,
                }
            }
        ])
        details = list(dataset)
        if details:
            response_object = {
                'status': Const.SUCCESS_CODE,
                'message': 'Username Exists'
            }
        else:
            response_object = {
                'status': Const.FAILURE_CODE,
                'message': 'Username Does Not Exists'
            }
        return response_object
    except Exception as e:
        response_object = {
            'status': Const.FAIL,
            'message': e
        }
    return response_object
