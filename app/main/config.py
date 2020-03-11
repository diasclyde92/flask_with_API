import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', '0Ngu@Rd_N3Xt+GeN3RaT10n')
    DEBUG = False


class LocalConfig(Config):
    TESTING = True
    DEBUG = True
    MONGODB_SETTINGS = {'DB': 'hackathon_local'}
    SECRET_KEY = 'flask+mongoengine=<3'


class DevelopmentConfig(Config):
    TESTING = True
    DEBUG = True
    MONGODB_SETTINGS = {'DB': 'hackathon_dev'}
    SECRET_KEY = 'flask+mongoengine=<3'


class TestingConfig(Config):
    DEBUG = False
    TESTING = True
    MONGODB_SETTINGS = {'DB': 'hackathon_test'}
    SECRET_KEY = 'flask+mongoengine=<3'


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    MONGODB_SETTINGS = {'DB': 'onguardNxt', 'USERNAME':'onguardNxt', 'PASSWORD':''}
    SECRET_KEY = '#Onguard123'



config_by_name = dict(
    LOCAL=LocalConfig,
    DEV=DevelopmentConfig,
    TEST=TestingConfig,
    PROD=ProductionConfig
)

key = Config.SECRET_KEY