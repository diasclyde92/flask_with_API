"""
* Name: login_service.py
* Description : School student and System users login related functions
* Author: www.opspl.com
* Date Created: 23rd Dec 2019
* Date Modified: 23rd Dec 2019
*
"""

from app.main.service.constants import *
from flask_jwt_extended import create_access_token
from flask_jwt_extended import decode_token
from flask import request
from app.main import bcrypt
import random
import uuid
import os


def gen_salt():
    salt = str(os.urandom(random.randint(14, 18))).lstrip('b')
    return salt


def hash_password(passwordString, salt):
    hhash = bcrypt.generate_password_hash(salt + passwordString)
    return hhash


def verify_password(provided, passwordHash, salt):
    return bcrypt.check_password_hash(passwordHash, salt + provided)


def generate_active_token(public_id, role, user_type):
    try:
        identity = {
            'publicId': public_id,
            'role': role,
            'userType': user_type
        }
        access_token = create_access_token(expires_delta=False, identity=identity)
        return access_token
    except Exception as e:
        return e


def fetch_role(user_id):
    data_set = UserTypes.objects.aggregate(*[
        {"$match": {"_id": user_id}}, {"$project": {"role": 1}}])
    details = list(data_set)
    return details[0]['role']


def login(data):
    if data['userType'].upper() == 'STAFF-USER':
        data_set = StaffUsers.objects.aggregate(*[
                {"$match": {"username": data['username'].upper()}},
                {"$project": {
                    'publicId': 1,
                    'password': 1,
                    'passwordSalt': 1,
                    'userTypeId': 1,
                    'security': 1
                }
                }
            ])
        details_staff_user = list(data_set)
        if len(details_staff_user) > 0:
            role = fetch_role(details_staff_user[0]['userTypeId'])
            verify = verify_password(data['password'], details_staff_user[0]['password'].encode('utf-8'),
                                     details_staff_user[0]['passwordSalt'])
            if not verify:
                response_object = {
                    'status': Const.FAIL,
                    'message': 'Incorrect username or password.'
                }
                return response_object
            is_pwd_onguard = verify_password(Const.ONGUARD, details_staff_user[0]['password'].encode('utf-8'),
                                             details_staff_user[0]['passwordSalt'])
            if is_pwd_onguard:
                response_object = {
                    'status': Const.SUCCESS,
                    'publicId': str(details_staff_user[0]['publicId']),
                    'role': role,
                    'userType': Const.STAFF_USER,
                    'setPassword': True,
                    'setSecurityQuestion': True
                }
                return response_object, Const.SUCCESS_CODE
            if not details_staff_user[0]['security']['mustChangeSecurityQuestion']:
                response_object = {
                    'status': Const.SUCCESS,
                    'publicId': str(details_staff_user[0]['publicId']),
                    'role': role,
                    'userType': Const.STAFF_USER,
                    'setPassword': False,
                    'setSecurityQuestion': True
                }
                return response_object, Const.SUCCESS_CODE
            token = generate_active_token(str(details_staff_user[0]['publicId']), role, data['userType'])
            response_object = {
                'status': Const.SUCCESS,
                'token': token,
                'publicId': str(details_staff_user[0]['publicId']),
                'role': role,
                'userType': Const.STAFF_USER,
                'setPassword': False,
                'setSecurityQuestion': False,
                'message': 'Successfully logged in.'
            }
            return response_object, Const.SUCCESS_CODE

        response_object = {
            'status': Const.FAIL,
            'message': 'Incorrect username or password.'
        }
        return response_object, Const.FAILURE_CODE

    elif data['userType'].upper() == 'STUDENT-SYSTEM-USER':
        data_set = Schools.objects.aggregate(*[
            {"$match": {"publicId": uuid.UUID(data['publicId'])}}, {"$project": {"id": 1}}])
        details_school_id = list(data_set)
        school_id = details_school_id[0]['_id']
        data_set = Schools.objects.aggregate(*[
            {"$limit": 1},
            {"$facet": {
                "collection1": [
                    {"$limit": 1},
                    {"$lookup": {
                        "from": "school_students",
                        "pipeline": [{"$match": {
                            "$and": [{"username": data['username'].upper()}, {"schoolId": school_id}]}}],
                        "as": "collection1"
                    }}
                ],
                "collection2": [
                    {"$limit": 1},
                    {"$lookup": {
                        "from": "system_users",
                        "pipeline": [{"$match": {
                            "$and": [{"username": data['username'].upper()}, {"schoolId": school_id}]}}],
                        "as": "collection2"
                    }}
                ]
            }},
            {"$project": {
                "data": {
                    "$concatArrays": [
                        {"$arrayElemAt": ["$collection1.collection1", 0]},
                        {"$arrayElemAt": ["$collection2.collection2", 0]}
                    ]
                }
            }},
            {"$unwind": "$data"},
            {"$replaceRoot": {"newRoot": "$data"}}
        ])
        details_student_system_user = list(data_set)
        if len(details_student_system_user) > 0:
            if 'userTypeId' in details_student_system_user[0]:
                role = fetch_role(details_student_system_user[0]['userTypeId'])
            else:
                role = 'STUDENT'
            verify = verify_password(data['password'], details_student_system_user[0]['password'].encode('utf-8'),
                                     details_student_system_user[0]['passwordSalt'])
            if not verify:
                response_object = {
                    'status': Const.FAIL,
                    'message': 'Incorrect username or password.'
                }
                return response_object, Const.FAILURE_CODE
            is_pwd_onguard = verify_password(Const.ONGUARD, details_student_system_user[0]['password'].encode('utf-8'),
                                             details_student_system_user[0]['passwordSalt'])
            if is_pwd_onguard:
                response_object = {
                    'status': Const.SUCCESS,
                    'publicId': str(details_student_system_user[0]['publicId']),
                    'role': role,
                    'userType': Const.STUDENT_SYSTEM_USER,
                    'setPassword': True,
                    'setSecurityQuestion': True
                }
                return response_object, Const.SUCCESS_CODE
            if not details_student_system_user[0]['security']['mustChangeSecurityQuestion']:
                response_object = {
                    'status': Const.SUCCESS,
                    'publicId': str(details_student_system_user[0]['publicId']),
                    'role': role,
                    'userType': Const.STUDENT_SYSTEM_USER,
                    'setPassword': False,
                    'setSecurityQuestion': True
                }
                return response_object, Const.SUCCESS_CODE
            token = generate_active_token(str(details_student_system_user[0]['publicId']), role, data['userType'])
            response_object = {
                'status': Const.SUCCESS,
                'token': token,
                'publicId': str(details_student_system_user[0]['publicId']),
                'role': role,
                'userType': Const.STUDENT_SYSTEM_USER,
                'setPassword': False,
                'setSecurityQuestion': False,
                'message': 'Successfully logged in.'
            }
            return response_object, Const.SUCCESS_CODE

        response_object = {
            'status': Const.FAIL,
            'message': 'Incorrect username or password.'
        }
        return response_object, Const.FAILURE_CODE

    else:
        response_object = {
            'status': Const.FAIL,
            'message': 'Incorrect username or password.'
        }
        return response_object, Const.FAILURE_CODE


def set_password(data):
    if data['userType'].upper() == Const.STAFF_USER:
        if data['password'] == data['confirmPassword'] and data['password'] != Const.ONGUARD:
            salt = gen_salt()
            password = hash_password(data['password'], salt)
            StaffUsers.objects(publicId=data['publicId']).update(set__password=password.decode('utf-8'),
                                                                 set__passwordSalt=salt)
            response_object = {
                'status': Const.SUCCESS,
                'message': 'Password set successfully.'
            }
            return response_object, Const.SUCCESS_CODE
        else:
            response_object = {
                'status': Const.FAIL,
                'message': 'Incorrect password.'
            }
            return response_object, Const.FAILURE_CODE

    elif data['userType'].upper() == 'STUDENT-SYSTEM-USER':
        if data['password'] == data['confirmPassword'] and data['password'] != Const.ONGUARD:
            salt = gen_salt()
            password = hash_password(data['password'], salt)
            SystemUsers.objects(publicId=data['publicId']).update(set__password=password.decode('utf-8'),
                                                                  set__passwordSalt=salt)
            SchoolStudents.objects(publicId=data['publicId']).update(set__password=password.decode('utf-8'),
                                                                     set__passwordSalt=salt)
            response_object = {
                'status': Const.SUCCESS,
                'message': 'Password set successfully.'
            }
            return response_object, Const.SUCCESS_CODE
        else:
            response_object = {
                'status': Const.FAIL,
                'message': 'Incorrect password.'
            }
            return response_object, Const.FAILURE_CODE

    else:
        response_object = {
            'status': Const.FAIL,
            'message': 'Incorrect password.'
        }
        return response_object, Const.FAILURE_CODE


def set_security_question_answer(data):
    try:
        if data['userType'].upper() == Const.STAFF_USER:
            data_set = SecurityQuestions.objects.aggregate(*[
                {"$match": {"publicId": uuid.UUID(data['questionId'])}},
                {"$project": {"id": 1}}])
            details = list(data_set)
            question_id = details[0]['_id']
            security = {'security': {
                    'mustChangeSecurityQuestion': True,
                    'securityQuestionAnswer': data['securityQuestionAnswer'],
                    'securityQuestion':
                        {
                            'questionId': question_id,
                            'questionText': data['text']
                        }}}
            StaffUsers.objects(publicId=data['publicId']).update(**security)
            token = generate_active_token(str(data['publicId']), data['role'], data['userType'])
            response_object = {
                'status': Const.SUCCESS,
                'token': token,
                'message': 'Question-Answer updated successfully'
            }
            return response_object, Const.SUCCESS_CODE

        elif data['userType'].upper() == 'STUDENT-SYSTEM-USER':
            data_set = SecurityQuestions.objects.aggregate(*[
                {"$match": {"publicId": uuid.UUID(data['questionId'])}},
                {"$project": {"id": 1}}])
            details = list(data_set)
            question_id = details[0]['_id']
            security = {'security': {
                'mustChangeSecurityQuestion': True,
                'securityQuestionAnswer': data['securityQuestionAnswer'],
                'securityQuestion':
                    {
                        'questionId': question_id,
                        'questionText': data['text']
                    }}}
            SchoolStudents.objects(publicId=data['publicId']).update(**security)
            SystemUsers.objects(publicId=data['publicId']).update(**security)
            token = generate_active_token(str(data['publicId']), data['role'], data['userType'])
            response_object = {
                'status': Const.SUCCESS,
                'token': token,
                'message': 'Question-Answer updated successfully'
            }
            return response_object, Const.SUCCESS_CODE

        else:
            response_object = {
                'status': Const.FAIL,
                'message': 'Incorrect password.'
            }
            return response_object, Const.FAILURE_CODE

    except Exception as e:
        response_object = {
            'status': Const.FAIL,
            'message': e
        }
        return response_object, Const.FAILURE_CODE


def change_password(data):
    try:
        token = request.headers['X-API-KEY']
        info = decode_token(token)
        public_id = info['identity']['publicId']
        user_type = info['identity']['userType']
        if user_type.upper() == 'STAFF-USER':
            for user in StaffUsers.objects(publicId=public_id):
                if data['newPassword'] == data['confirmPassword']:
                    verify = verify_password(data['oldPassword'], user.password.encode('utf-8'), user.passwordSalt)
                    if verify is True:
                        salt = gen_salt()
                        password = hash_password(data['newPassword'], salt)
                        StaffUsers.objects(publicId=public_id).update(set__password=password.decode('utf-8'),
                                                                      set__passwordSalt=salt)
                        response_object = {
                            'status': Const.SUCCESS,
                            'message': 'Password changed successfully'
                        }
                        return response_object, Const.SUCCESS_CODE
                    else:
                        response_object = {
                            'status': Const.FAIL,
                            'message': 'Invalid Old password'
                        }
                        return response_object, Const.FAILURE_CODE
                else:
                    response_object = {
                        'status': Const.FAIL,
                        'message': 'Password do not match'
                    }
                    return response_object, Const.FAILURE_CODE

            response_object = {
                'status': Const.FAIL,
                'message': 'User not found'
            }
            return response_object, Const.FAILURE_CODE

        elif user_type.upper() == 'STUDENT-SYSTEM-USER':
            if len(SchoolStudents.objects(publicId=public_id)) > 0:
                for user in SchoolStudents.objects(publicId=public_id):
                    if data['newPassword'] == data['confirmPassword']:
                        verify = verify_password(data['oldPassword'], user.password.encode('utf-8'), user.passwordSalt)
                        if verify is True:
                            salt = gen_salt()
                            password = hash_password(data['newPassword'], salt)
                            SchoolStudents.objects(publicId=public_id).update(set__password=password.decode('utf-8'),
                                                                              set__passwordSalt=salt)
                            response_object = {
                                'status': Const.SUCCESS,
                                'message': 'Password changed successfully'
                            }
                            return response_object, Const.SUCCESS_CODE
                        else:
                            response_object = {
                                'status': Const.FAIL,
                                'message': 'Invalid Old password'
                            }
                            return response_object, Const.FAILURE_CODE
                    else:
                        response_object = {
                            'status': Const.FAIL,
                            'message': 'Password do not match'
                        }
                        return response_object, Const.FAILURE_CODE

                response_object = {
                    'status': Const.FAIL,
                    'message': 'User not found'
                }
                return response_object, Const.FAILURE_CODE
            elif len(SystemUsers.objects(publicId=public_id)) > 0:
                for user in SystemUsers.objects(publicId=public_id):
                    if data['newPassword'] == data['confirmPassword']:
                        verify = verify_password(data['oldPassword'], user.password.encode('utf-8'), user.passwordSalt)
                        if verify is True:
                            salt = gen_salt()
                            password = hash_password(data['newPassword'], salt)
                            SystemUsers.objects(publicId=public_id).update(set__password=password.decode('utf-8'),
                                                                           set__passwordSalt=salt)
                            response_object = {
                                'status': Const.SUCCESS,
                                'message': 'Password changed successfully'
                            }
                            return response_object, Const.SUCCESS_CODE
                        else:
                            response_object = {
                                'status': Const.FAIL,
                                'message': 'Invalid Old password'
                            }
                            return response_object, Const.FAILURE_CODE
                    else:
                        response_object = {
                            'status': Const.FAIL,
                            'message': 'Password do not match'
                        }
                        return response_object, Const.FAILURE_CODE

                response_object = {
                    'status': Const.FAIL,
                    'message': 'User not found'
                }
                return response_object, Const.FAILURE_CODE
            else:
                response_object = {
                    'status': Const.FAIL,
                    'message': 'User not found'
                }
                return response_object, Const.FAILURE_CODE

        else:
            response_object = {
                'status': Const.FAIL,
                'message': 'User not found'
            }
            return response_object, Const.FAILURE_CODE

    except Exception as e:
        response_object = {
            'status': Const.FAIL,
            'message': e
        }
        return response_object, Const.FAILURE_CODE


def individual_reset_password(data):
    try:
        salt = gen_salt()
        data['password'] = hash_password('onguard', salt).decode('utf-8')
        data['passwordSalt'] = salt
        StaffUsers.objects(publicId=data['publicId']).update(**data)
        response_object = {
            'status': Const.SUCCESS,
            'message': 'Password reset successfully.'
        }
        return response_object, Const.SUCCESS_CODE
    except Exception as e:
        response_object = {
            'status': Const.FAIL,
            'message': e
        }
        return response_object, Const.FAILURE_CODE

