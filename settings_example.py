# encoding: utf-8
import os

# URI de conexão no Mongo
AMBIENTE = 'dev'
#
MONGO_HOST = os.environ.get('MONGO_HOST', 'db.mycompany.com:27017')
MONGO_USERNAME = os.environ.get('MONGO_USERNAME')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')
MONGO_DBNAME = os.environ.get('MONGO_DBNAME', 'tzion')
DEBUG = os.environ.get('DEBUG')
SOURCEZONE = os.environ.get('SOURCEZONE', 'paloalto_source_zone')
DESTZONE = os.environ.get('DESTZONE', 'paloalto_destination_zone')

#AUTH_URI
AUTH_URI = os.environ.get('AUTH_URI', 'https://auth-server.mycompany.com/bind') 
AUTH_GROUP = os.environ.get('AUTH_GROUP', 'https://auth-server.mycompany.com/group/testgroup') 

#Identifica FW de DEV / PROD
FW_HOST = os.environ.get('FW_HOST','vsys-name')
FW_URL = "https://paloalto-firewall-name.mycompany.com//api/?"

#CHAVE AUTHENTICACAO
FW_KEY = "palo-alto-key"
#LOG_NAME = "tzion"
