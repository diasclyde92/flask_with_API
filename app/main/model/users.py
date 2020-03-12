from .. import mdb
from app.main.service.constants import *

GENDER = (Const.MALE,Const.FEMALE)

class Name(mdb.EmbeddedDocument):
    firstName = mdb.StringField()
    lastName = mdb.StringField()

class Users(mdb.Document):
    publicId = mdb.UUIDField(binary=True)
    username = mdb.StringField()
    password = mdb.StringField()
    name = mdb.EmbeddedDocumentField(Name)
    profile_image = mdb.StringField()
    deleted = mdb.BooleanField()
    date_of_birth = mdb.DateTimeField()
    gender = mdb.StringField(choices=GENDER)
    email = mdb.StringField()
    contact = mdb.StringField()