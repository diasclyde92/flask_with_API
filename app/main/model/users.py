from .. import mdb

GENDER = ('MALE', 'FEMALE')

class Users(mdb.Document):
    publicId = mdb.UUIDField(binary=True)
    username = mdb.StringField()
    password = mdb.StringField()
    name = mdb.StringField()
    profile_image = mdb.StringField()
    deleted = mdb.BooleanField()
    date_of_birth = mdb.DateTimeField()
    gender = mdb.StringField(choices=GENDER)
    email = mdb.StringField()
    contact = mdb.StringField()