# -*- coding: utf-8 -*-
import logging
from logging.handlers import SysLogHandler
import pymongo
from pymongo import MongoClient
from datetime import datetime
import settings
import sys


stdout_logger = logging.getLogger('TZION')
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
out_hdlr.setLevel(logging.INFO)
stdout_logger.addHandler(out_hdlr)
stdout_logger.setLevel(logging.INFO)

stderror_logger = logging.getLogger('TZION')
err_hdlr = logging.StreamHandler(sys.stderr)
err_hdlr.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
err_hdlr.setLevel(logging.ERROR)
stderror_logger.addHandler(err_hdlr)
stderror_logger.setLevel(logging.ERROR)

uri = "mongodb://%s:%s@%s/%s"% (settings.MONGO_USERNAME, settings.MONGO_PASSWORD, settings.MONGO_HOST, settings.MONGO_DBNAME)
client = MongoClient(uri)
db = client['tzion']
collection = db.servicerules
collection2 = db.hosts_nets
collection3 = db.app_urls
collection4 = db.owners
collection5 = db.commit

#Essa funcao recebera o nome da regra que devera ser criada. Caso a regra ja exista, vira acompanhada da Flag "append"
def insert_rules_owners(user,ip,data):    
    if data.has_key("rule_exists"):#trabalhando com uma regra que ja existe. Apenas colocar hosts novos nela
        try:
            sources_owners = list(collection4.find({"rule_name":data["name"]},{"sources_owners.%s"%user:1,"_id":0}))            
        except pymongo.errors.PyMongoError as e:
            return {"Error":e}
        if sources_owners[0]["sources_owners"] == {}:
            try:
                collection4.update({"rule_name":data["name"]},{"$set": {"sources_owners.%s"%user: data["sources"]}})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s was updated with sources %s for sources_owner %s.'""",ip,user,data["name"],user,data["sources"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='Rule %s wasn't updated with sources %s for source_owner %s. Error: %s'""",ip,user,data["name"],user,data["sources"],e)                
                return {"Error":e}
        else:
            try:
                collection4.update({"rule_name":data["name"]},{"$pushAll": {"sources_owners.%s"%user: data["sources"]}})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s was updated with sources %s for source_owner %s.'""",ip,user,data["name"],user,data["sources"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='Rule %s wasn't updated with sources %s for source_owner %s. Error: %s'""",ip,user,data["name"],user,data["sources"],e)                
                return {"Error":e}
    else:
        try:
            collection4.insert({"rule_name":data["name"],"own":user,"sources_owners":{user:data["sources"]}})
            stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Rule %s was created with owner %s and sources_owners %s : %s.'""",ip,user,data["name"],data["sources"],user)
        except pymongo.errors.PyMongoError as e:
            stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Rule %s wasn't created with source_owner %s and sources %s. Error: %s'""",ip,user,data["name"],data["sources"],user,e)                
            return {"Error":e}
    client.close()
    return {"Collection":"OK"}
    
def remove_rules_owners(user,ip,data):
    try:
        sources_owners = list(collection4.find({"rule_name":data["name"]},{"own":1,"sources_owners":1,"_id":0}))
        if sources_owners == []:
            collection.close()
            return {"Error":"Rule %s not Found"%data["name"]}
    except pymongo.errors.PyMongoError as e:
        return {"Error":e}
    #O usuario esta tentando apagar uma regra inteira. So poderar fazer se for dono da regra e nao tiver hosts de outros usuarios. Nesse caso, a regra nao sera apagada.
    if data.has_key("DEL"):
        if sources_owners[0]["own"] == user:
            if sources_owners[0]["sources_owners"].has_key(user):
                if len(sources_owners[0]["sources_owners"]) > 1:#alem do usuario encontrado, existem outros sources cadastrados para outros usuario.N sera apagado assim
                    return {"Forbidden":"Forbidden"}
                else:
                    try:
                        collection.remove({"name":data["name"]})
                        collection4.remove({"rule_name":data["name"]})
                        client.close()
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='OK',reason='DB Rule owner %s deleted.'""",ip,user,data["name"])
                        return {"Collection":"OK"}
                    except pymongo.errors.PyMongoError as e:
                        stdout_logger.error("""app='TZION',source='%s',username='%s',action='remove',status='ERROR',reason='DB Rule owner %s was not deleted. Error: %s'""",ip,user,data["name"],e)                
                        return {"Error":e}
            else:
                if sources_owners[0]["sources_owners"] == {}:
                    try:
                        collection.remove({"name":data["name"]})
                        collection4.remove({"rule_name":data["name"]})
                        client.close()
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='OK',reason='DB Rule owner %s deleted.'""",ip,user,data["name"])
                        return {"Collection":"OK"}
                    except pymongo.errors.PyMongoError as e:
                        stdout_logger.error("""app='TZION',source='%s',username='%s',action='remove',status='ERROR',reason='DB Rule owner %s was not deleted. Error: %s'""",ip,user,data["name"],e)                
                        return {"Error":e}
        else:
            client.close()
            return {"Forbidden":"Unauthorized removal of the rule %s. There are sources from other user(s) in the rule."%data["name"]}  
            
    #Aqui o usuario nao tera mais nenhum objeto associado ao seu nome. O campo de owners pertencente ao usuario devera ser removido.
    if data.has_key("set_end"):
        try:
            collection4.update({"rule_name":data["name"]},{"$unset": {"sources_owners.%s"%user:1}})
            client.close()
            stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='OK',reason='DB Rule %s sources_owners.%s deleted.'""",ip,user,data["name"],user)
            return {"Collection":"OK"}
        except pymongo.errors.PyMongoError as e:
            stdout_logger.error("""app='TZION',source='%s',username='%s',action='remove',status='ERROR',reason='DB Rule %s sources_owners.%s not deleted. Error: %s'""",ip,user,data["name"],user,e)                
            return {"Error":e}    
    #Aqui o usuario tenta apagar partes da regra (so podera apagar o que pertence a ele proprio).
    if sources_owners[0]["sources_owners"].has_key(user):
        try:
            collection4.update({"rule_name":data["name"]},{"$set": {"sources_owners.%s"%user: data["set"]}})
            stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s now has the sources %s for sources_owner %s.'""",ip,user,data["name"],data["set"],user)
            return {"Collection":"OK"}
        except pymongo.errors.PyMongoError as e:
            stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='Rule %s wasn't updated with sources %s for source_owner %s. Error: %s'""",ip,user,data["name"],data["set"],user,e)                
            return {"Error":e}
    else:
        return {"Forbidden":"Unauthorized removal sources %s, because user %s is not the owner of sources."%(data,user)}
        
def db_call(user,ip,data):    
    if data["collection"] == "collection":
        if data.has_key("find"):
            try:
                doc = list(collection.find(data["find"][0],data["find"][1]))
                return {"Collection":doc}
            except pymongo.errors.PyMongoError as e:
                return {"Error":e}
        if data.has_key("push"):
            try:
                collection.update({"name":data["name"]},{"$pushAll": {"source.address": data["push"]}})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB Rule %s updated with element(s) %s'""",ip,user,data["name"],data["push"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB Rule %s wasn't updated with element(s) %s. Error: %s'""",ip,user,data["name"],data["push"],e)                
                return {"Error":e}
        if data.has_key("set"):
            try:
                collection.update({"name":data["name"]},{"$set": {"source.address":data["set"]}})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB Rule %s updated with element(s) %s'""",ip,user,data["name"],data["set"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB Rule %s wasn't updated with element(s) %s. Error: %s'""",ip,user,data["name"],data["set"],e)                
                return {"Error":e}        
        if data.has_key("insert"):
            try:
                collection.insert(data["insert"])
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB Rule %s inserted properly.'""",ip,user,data["insert"]["name"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB Rule %s was not inserted properly. Error: %s'""",ip,user,data["insert"]["name"],e)                
                return {"Error":e}
        if data.has_key("remove"):
            try:
                collection.remove({"name":data["remove"]})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB Rule %s deleted.'""",ip,user,data["remove"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB Rule %s was not deleted. Error: %s'""",ip,user,data["remove"],e)                
                return {"Error":e}
    if data["collection"] == "collection2":
        if data.has_key("find"):
            try:
                doc = list(collection2.find(data["find"][0],data["find"][1]))
                return {"Collection":doc}
            except pymongo.errors.PyMongoError as e:
                return {"Error":e}        
        if data.has_key("insert"):
            try:
                collection2.insert({"address":data["insert"]})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='DB object %s inserted properly.'""",ip,user,data["insert"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='DB object %s was not inserted properly. Error: %s'""",ip,user,data["insert"],e)                
                return {"Error":e}
    if data["collection"] == "collection3":
        if data.has_key("find"):
            try:
                doc = list(collection3.find(data["find"][0],data["find"][1]))
                return {"Collection":doc}
            except pymongo.errors.PyMongoError as e:
                return {"Error":e}
        if data.has_key("insert"):
            try:
                collection3.insert(data["insert"])
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='DB Rule %s inserted properly.'""",ip,user,data["insert"]["regra_name"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='DB Rule %s was not inserted properly. Error: %s'""",ip,user,data["insert"]["regra_name"],e)                
                return {"Error":e}
        if data.has_key("remove"):
            try:
                collection3.remove({"app_name":data["remove"]})
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB APP %s deleted.'""",ip,user,data["remove"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB APP %s wasn't deleted. Error: %s'""",ip,user,data["remove"],e)
                return {"Error":e}
    if data["collection"] == "collection4":
        if data.has_key("find"):
            try:
                doc = list(collection4.find(data["find"][0],data["find"][1]))
                return {"Collection":doc}
            except pymongo.errors.PyMongoError as e:
                return {"Error":e}
    if data["collection"] == "collection5":
        if data.has_key("find"):
            try:
                doc = list(collection5.find(data["find"][0],data["find"][1]))
                return {"Collection":doc}
            except pymongo.errors.PyMongoError as e:
                return {"Error":e}
        if data.has_key("set"):
            try:
                collection5.update(data["set"][0],data["set"][1],True,multi=True)
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='DB Collection Commit updated!'""",ip,user)
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='DB Collection Commit wasn't updated. Error: %s'""",ip,user,e)                
                return {"Error":e}
        if data.has_key("insert"):
            try:
                collection5.insert(data["insert"])
                stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Collection commit updated with rule_id %s properly.'""",ip,user,data["insert"]["rule_id"])
            except pymongo.errors.PyMongoError as e:
                stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Collection commit not updated with rule_id %s. Error: %s'""",ip,user,data["insert"]["rule_id"],e)                
                return {"Error":e}
    client.close()
    return {"Collection":"OK"}
