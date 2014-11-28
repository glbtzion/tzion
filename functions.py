# -*- coding: utf-8 -*-
import json, xmltodict, urllib, requests, logging, re, pymongo
from logging.handlers import SysLogHandler
from bson.objectid import ObjectId
from pymongo import MongoClient
from rules_firewall import *
from rules_db import *
from commit_control import *
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

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

def autenticacao(user,password,ip):
    url_auth = settings.AUTH_URI
    data = {"username":user,"password":password,"twofactor":"disable"}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    req = requests.post(url_auth, data=json.dumps(data), headers=headers, verify=False)
    if req.status_code == 200:
        stdout_logger.info("""app='TZION',source='%s',username='%s',action='login',status='OK',reason='user %s authenticated'""",ip,user,user)
        return "200 OK"
    else:
        stderror_logger.error("""app='TZION',source='%s',username='%s',action='login',status='FAILED',reason='wrong username or password'""",ip,user)
        return "%s ERROR"%(req.status_code)

def grupo(user,password,ip):
    url_group = settings.AUTH_GROUP
    data = {"username":user,"password":password,"twofactor":"disable"}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    req = requests.get(url_group, data=json.dumps(data), headers=headers, verify=False)
    if req.status_code == 200:
        stdout_logger.info("""app='TZION',source='%s',username='%s',action='login',status='OK',reason='user %s allowed on group'""",ip,user,user)
        return "200 OK"
    else:
        stderror_logger.error("""app='TZION',source='%s',username='%s',action='login',status='FAILED',reason='user %s not allowed on group'""",ip,user,user)
        return "%s ERROR"%(req.status_code)
        
def buscar_regra(user,ip,regra):
    valor = [] # Verificando se a regra em questao ja existe. A busca no banco sera atraves da origem do destino e do metodo de busca
    valor2 = []
    if not (regra.has_key("method")):
        stderror_logger.error("""app='TZION',source='%s',username='%s',action='search',status='ERROR',reason='Search method not reported.'""",ip,user)
        return JSONEncoder().encode({"Error:":"Search method not reported."})
    if regra.has_key("name"):
        string_db = {"find":[{"name":regra["name"]},{"name":1,"source.address":1,"destination.address":1,"app":1,"service":1,"_id":0}],"collection":"collection"}
        documento = db_call(user,ip,string_db)
        if documento.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})
        documento = documento["Collection"]
        if documento == []:
            return JSONEncoder().encode({"Success":"Rule %s not found."})%(regra["name"])
        else:
            string_db = {"find":[{"regra_name":regra["name"]},{"_id":0}],"collection":"collection3"}
            documento2 = db_call(user,ip,string_db)
            if documento2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            documento2 = documento2["Collection"]
	    if documento2 != []:
                if documento2[0].has_key("app_name"):
                    dic_regra_completa = {documento[0]["name"]:{"source.address":documento[0]["source"]["address"],"destination.address":documento[0]["destination"]["address"],"app":documento[0]["app"],"parent-app":documento2[0]["parent-app"],"service":documento[0]["service"],"url":documento2[0]["url"]}}
                else:
                    dic_regra_completa = {documento[0]["name"]:{"source.address":documento[0]["source"]["address"],"destination.address":documento[0]["destination"]["address"],"app":documento[0]["app"],"service":documento[0]["service"]}}
	    else:
                dic_regra_completa = {documento[0]["name"]:{"source.address":documento[0]["source"]["address"],"destination.address":documento[0]["destination"]["address"],"app":documento[0]["app"],"service":documento[0]["service"]}}
            return JSONEncoder().encode(dic_regra_completa)
    for key in regra.keys():
        if (key == "url"):
            for date in regra[key]:
                valor2.append({key:date})
        if (key == "parent-app"):
            valor2.append({key:regra[key]})
        if (key == "source") or (key == "destination"):
            var = "%s.address"%(key)
            for date in regra[key]:
                valor.append({var:date})
        if (key == "service") or (key == "app"):
            for date in regra[key]:
                valor.append({key:date})
    result = {}
    documentos = []
    documentos2 = []
    if regra["method"] == "exact":
        if valor != []:
            string_db = {"find":[{"$and":valor},{"_id":0}],"collection":"collection"}
            documentos = db_call(user,ip,string_db)
            if documentos.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            documentos = documentos["Collection"]    
            if regra.has_key("source"):#se qualquer if falhar, invalida as entradas pois documentos sempre sera vazio
                documentos = [x for x in documentos if (set(regra["source"]) == set(x["source"]["address"]))]
            if regra.has_key("destination"):
                documentos = [x for x in documentos if (set(regra["destination"]) == set(x["destination"]["address"]))]
            if regra.has_key("app"):
                documentos = [x for x in documentos if (set(regra["app"]) == set(x["app"]))]
            if regra.has_key("service"):
                documentos = [x for x in documentos if (set(regra["service"]) == set(x["service"]))]
        if valor2 != []:
            string_db = {"find":[{"$and":valor2},{"_id":0}],"collection":"collection3"}
            documentos2 = db_call(user,ip,string_db)
            if documentos2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            documentos2 = documentos2["Collection"]
            if regra.has_key("url"):
                documentos2 = [x for x in documentos2 if (set(regra["url"]) == set(x["url"]))]
            if regra.has_key("parent-app"):
                documentos2 = [x for x in documentos2 if (set(regra["parent-app"]) == set(x["parent-app"]))]

        if documentos != []:
            if documentos2 != []:
                for lista in documentos:
                    for lista2 in documentos2:
                        if lista["name"] == lista2["regra_name"]:
                            result[lista["name"]] = {}
                            result[lista["name"]]["source"] = lista["source"]["address"]
                            result[lista["name"]]["destination"] = lista["destination"]["address"]
                            result[lista["name"]]["url"] = lista2["url"]
                            result[lista["name"]]["app"] = lista["app"]
                            result[lista["name"]]["service"] = lista["service"]
                            result[lista["name"]]["parent-app"] = lista2["parent-app"]
            else:
                for lista in documentos:
                    result[lista["name"]] = {}
                    string_db = {"find":[{"regra_name":lista["name"]},{"_id":0}],"collection":"collection3"}
                    collection_teste = db_call(user,ip,string_db)
                    if collection_teste.has_key("Error"):
                        return JSONEncoder().encode({"Error":"Can't connect with DB."})
                    collection_teste = collection_teste["Collection"]
                    if collection_teste == []:
                        result[lista["name"]]["source"] = lista["source"]["address"]
                        result[lista["name"]]["destination"] = lista["destination"]["address"]
                        result[lista["name"]]["app"] = lista["app"]
                        result[lista["name"]]["service"] = lista["service"]
                    else:
                        result[lista["name"]]["source"] = lista["source"]["address"]
                        result[lista["name"]]["destination"] = lista["destination"]["address"]
                        result[lista["name"]]["url"] = collection_teste[0]["url"]
                        result[lista["name"]]["app"] = lista["app"]
                        result[lista["name"]]["parent-app"] = collection_teste[0]["parent-app"]
                        result[lista["name"]]["service"] = lista["service"]
        else:
            if documentos2 != []:
                for lista2 in documentos2:
                    result[lista2["regra_name"]] = {}
                    string_db = {"find":[{"name":lista2["regra_name"]},{"_id":0}],"collection":"collection"}
                    collection_teste = db_call(user,ip,string_db)
                    if collection_teste.has_key("Error"):
                        return JSONEncoder().encode({"Error":"Can't connect with DB."})
                    collection_teste = collection_teste["Collection"]
                    if collection_teste == []:
                        result = {}
                    else:
                        result[lista2["regra_name"]]["source"] = collection_teste[0]["source"]["address"]
                        result[lista2["regra_name"]]["destination"] = collection_teste[0]["destination"]["address"]
                        result[lista2["regra_name"]]["url"] = lista2["url"]
                        result[lista2["regra_name"]]["app"] = lista2["app_name"]
                        result[lista2["regra_name"]]["service"] = collection_teste[0]["service"]
                        result[lista2["regra_name"]]["parent-app"] = lista2["parent-app"]
            
    if regra["method"] == "any":
        if valor != []:
            string_db = {"find":[{"$or":valor},{"_id":0}],"collection":"collection"}
            documentos = db_call(user,ip,string_db)
            if documentos.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            documentos = documentos["Collection"]
        if valor2 != []:
            string_db = {"find":[{"$or":valor2},{"_id":0}],"collection":"collection3"}
            documentos2 = db_call(user,ip,string_db)
            if documentos2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            documentos2 = documentos2["Collection"]
    if documentos != []:
        if documentos2 != []:
            for lista in documentos:
                for lista2 in documentos2:
                    if lista["name"] == lista2["regra_name"]:
                        result[lista["name"]] = {}
                        result[lista["name"]]["source"] = lista["source"]["address"]
                        result[lista["name"]]["destination"] = lista["destination"]["address"]
                        result[lista["name"]]["url"] = lista2["url"]
                        result[lista["name"]]["app"] = lista2["app_name"]
                        result[lista["name"]]["parent-app"] = lista2["parent-app"]
                        result[lista["name"]]["service"] = lista["service"]
        else:
            for lista in documentos:
                string_db = {"find":[{"regra_name":lista["name"]},{"_id":0}],"collection":"collection3"}
                collection_teste = db_call(user,ip,string_db)
                if collection_teste.has_key("Error"):
                    return JSONEncoder().encode({"Error":"Can't connect with DB."})
                collection_teste = collection_teste["Collection"]
                result[lista["name"]] = {}
                if collection_teste != []:
                    result[lista["name"]]["source"] = lista["source"]["address"]
                    result[lista["name"]]["destination"] = lista["destination"]["address"]
                    result[lista["name"]]["app"] = lista["app"]
                    result[lista["name"]]["url"] = collection_teste[0]["url"]
                    result[lista["name"]]["parent-app"] = collection_teste[0]["parent-app"]
                    result[lista["name"]]["service"] = lista["service"]
                else:
                    result[lista["name"]]["source"] = lista["source"]["address"]
                    result[lista["name"]]["destination"] = lista["destination"]["address"]
                    result[lista["name"]]["app"] = lista["app"]
                    result[lista["name"]]["service"] = lista["service"]
    else:
        if documentos2 != []:
            for lista2 in documentos2:
                result[lista2["regra_name"]] = {}
                string_db = {"find":[{"name":lista2["regra_name"]},{"_id":0}],"collection":"collection"}
                collection_teste = db_call(user,ip,string_db)
                if collection_teste.has_key("Error"):
                    return JSONEncoder().encode({"Error":"Can't connect with DB."})
                collection_teste = collection_teste["Collection"]
                if collection_teste == []:
                    result = {}
                else:
                    result[lista2["regra_name"]]["source"] = collection_teste[0]["source"]["address"]
                    result[lista2["regra_name"]]["destination"] = collection_teste[0]["destination"]["address"]
                    result[lista2["regra_name"]]["url"] = lista2["url"]
                    result[lista2["regra_name"]]["app"] = lista2["app_name"]
                    result[lista2["regra_name"]]["service"] = collection_teste[0]["service"]
                    result[lista2["regra_name"]]["parent-app"] = lista2["parent-app"]
    if result == {}:
        return JSONEncoder().encode({"Success":{}})
    else:
        return JSONEncoder().encode({"Success":result})

        
def inserir_regra_L7(user,ip,regra):
    if regra.has_key("name"):
        return_db = db_call(user,ip,{"find":[{"name":regra["name"]},{"_id":0}],"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})
        if return_db["Collection"] != []:
            return JSONEncoder().encode({"Error":"Firewall rule %s already exists."})%(regra["name"])
    else:
        return JSONEncoder().encode({"Error":"Name to rule uninformed."})
    valor = [] # Verificando se a regra em questao ja existe. A busca no banco sera atraves das urls de destino, app e service  
    hosts_will_add = []
    if regra.has_key("source"):
        valor.extend([{"url":x} for x in regra["url"]])
        if regra.has_key("parent-app"):
            valor.append({"parent-app":regra["parent-app"]})
        else:
            return JSONEncoder().encode({"Error":"No parent-app reported."})
    else:
        return JSONEncoder().encode({"Error":"No sources reported."})    
    return_db_3 = db_call(user,ip,{"find":[{"$and":valor},{"_id":0}],"collection":"collection3"})
    if return_db_3.has_key("Error"):
        return JSONEncoder().encode({"Error":"Can't connect with DB."})
    
    control = [x for x in return_db_3["Collection"] if (set(x["url"]) == set(regra["url"]))]
    if control != []:
        nome_regra_existente = return_db_3["Collection"][0]["regra_name"]
        return_db = db_call(user,ip,{"find":[{"name":nome_regra_existente},{"_id":0}],"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})            
        if return_db["Collection"] == []: #ate aqui descobrimos que a app esta criada com as urls em questao mas nao sabemos se esta em uso por uma regra
            n_contido_sources = [regra["source"],"insert"]
        else:
            n_contido_sources = list(set(regra["source"]) - set(return_db["Collection"][0]["source"]["address"]))
        if n_contido_sources == []:
            return JSONEncoder().encode({"Error":"There is already a rule named %s that allows access from the source address to the desired site"})%(nome_regra_existente)
        for entry in regra["source"]:
            return_db_2 = db_call(user,ip,{"find":[{"address":entry},{"_id":0}],"collection":"collection2"})
            if return_db_2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            if return_db_2["Collection"] == []:
                return_db = db_call(user,ip,{"insert":entry,"collection":"collection2"})
                if return_db.has_key("Error"):
                    return JSONEncoder().encode({"Error":"DB object %s was not inserted."})%(entry)
                hosts_will_add.append(entry)
        retorno_funcao = inserir_hosts_firewall(hosts_will_add)
        if retorno_funcao != []:
            stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='Error',reason='Object(s) %s not included on the firewall.'""",ip,user,hosts_will_add)
            return JSONEncoder().encode({"Error":"Could not insert the object: %s on Firewall"})%(hosts_will_add)
        else:
            dic_regra = {}      
            dic_regra["vsys"] = settings.FW_HOST
            dic_regra["device"] = "fw-pa-dc-rj-11"
            dic_regra["source"] = {}
            dic_regra["source"]["zone"] = settings.SOURCEZONE
            dic_regra["source"]["address"] = regra["source"]
            dic_regra["source"]["user"] = "any"
            dic_regra["source"]["hip"] = "any"
            dic_regra["destination"] = {}
            dic_regra["destination"]["zone"] = settings.DESTZONE
            dic_regra["destination"]["address"] = ["any"]
            if regra.has_key("app_name"):
                dic_regra["app"] = [regra["app_name"]]
            else:
                return JSONEncoder().encode({"Error":"Application Name Unknown"})    
            dic_regra["service"] = ["application-default"]
            dic_regra["profile"] = "any"
            dic_regra["options"] = "any"
            if regra.has_key("desc"):
                dic_regra["desc"] = regra["desc"]
            else:
                now = datetime.now()
                data = "%s"%now.day + "/" + "%s"%now.month + "/" + "%s"%now.year + " as " + "%s"%now.hour + ":" + "%s"%now.minute + ":" + "%s"%now.second  
                dic_regra["desc"] = "Rule inserted by %s:%s in: %s "%(ip,user,data)
            dic_regra["name"] = "%s"%regra["name"]
            dic_regra["tag"] = "API"
       
    	    if len(n_contido_sources) == 2:#trata-se de uma regra nova. Apenas a app ja existe.
            
                return_control_rules = insert_rules_owners(user,ip,{"name":regra["name"],"sources":regra["source"]})
                if return_control_rules.has_key("Error"):
                            return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
                
                return_db = db_call(user,ip,{"insert":dic_regra,"collection":"collection"})
                if return_db.has_key("Error"):
                    return JSONEncoder().encode({"Error":"DB rule %s was not inserted."})%(regra["name"])
                retorno_regra = inserir_regra_firewall(dic_regra)
                if retorno_regra != []:
                    stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='Error',reason='Rule %s not inserted.'""",ip,user,regra["name"])
                    return JSONEncoder().encode({"Error":"Could not insert rule: %s. Contact the security team."})%(regra["name"])
                else:
                    retorno_cleanup = deladd_cleanup_firewall()
                    if retorno_cleanup == []:
                        result_commit = commit_vsys()
                        if result_commit != []:
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s inserted in Firewall but uncommitted'""",ip,user,dic_regra["name"])  
                            return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted."})%(dic_regra["name"])
                        else:
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Rule %s inserted into the Firewall.'""",ip,user,dic_regra["name"])
                            return JSONEncoder().encode({"Success":"Rule: %s inserted in Firewall!"})%(dic_regra["name"])
                    else:
                        stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Error removing Clean_UP rule.'""",ip,user)
                        return JSONEncoder().encode({"Error":"Problems with Clean_UP rule. Contact the security team immediately."})                        
    	    else:
                return_control_rules = insert_rules_owners(user,ip,{"name":nome_regra_existente,"sources":n_contido_sources,"rule_exists":"yes"})
                if return_control_rules.has_key("Error"):
                            return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
                return_db = db_call(user,ip,{"push":n_contido_sources,"name":nome_regra_existente,"collection":"collection"})
                if return_db.has_key("Error"):
                    return JSONEncoder().encode({"Error":"Rule %s wasn't updated with new source element(s) %s."})%(nome_regra_existente,n_contido_sources)
                retorno_regra_append = inserir_regra_firewall({"source_append":n_contido_sources,"name":nome_regra_existente})
                if retorno_regra_append != []:
                    stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Rule %s not updated with the element(s )%s.'""",ip,user,regra["name"],n_contido_sources)
                    word = ""
                    for value in n_contido_sources:
                        word = word + " %s,"%value
                    return JSONEncoder().encode({"Error":"Could not update the rule: %s, with source(s): %s."})%(nome_regra_existente,word[:-1])
                else:
                    lock_commit = commit_lock(lock_control())
                    if lock_commit["response"] == "OK":
                        result_commit = commit_vsys()
                        if result_commit != []:
                            id_commit = commit_control(user,ip,"Uncommitted")
                            if type(id_commit) != int:
                                return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s has been updated but uncommitted. ID Commit = %s'""",ip,user,nome_regra_existente,id_commit)  
                            return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted. ID Commit = %s"})%(nome_regra_existente,id_commit)
                        else:
                            id_commit = commit_control(user,ip,"Committed")
                            if type(id_commit) != int:
                                return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                            update_collection = commit_update(id_commit)
                            if update_collection.has_key("Error"):
                                return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was updated in Firewall with source(s): %s.'""",ip,user,nome_regra_existente,n_contido_sources)
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s has been updated with the source(s): %s. ID Commit = %s'""",ip,user,nome_regra_existente,n_contido_sources,id_commit)
                            return JSONEncoder().encode({"Success":"Rule %s has been updated in Firewall! Commit ID = %s"})%(nome_regra_existente,id_commit)
                    else:
                        id_commit = commit_control(user,ip,"Uncommitted")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,nome_regra_existente)
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='ALERT',reason='Rule %s has been updated but uncommitted. ID Commit = %s'""",ip,user,nome_regra_existente,id_commit)  
                        return JSONEncoder().encode({"Alert":"Rule: %s has been updated in Firewall but uncommitted. ID Commit = %s"})%(nome_regra_existente,id_commit)
    else:
        dic_regra = {}
        valor = regra["source"]
        for dado in valor:
            return_db_2 = db_call(user,ip,{"find":[{"address":dado},{"_id":0}],"collection":"collection2"})
            if return_db_2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            if return_db_2["Collection"] == []:
                return_db = db_call(user,ip,{"insert":dado,"collection":"collection2"})
                if return_db.has_key("Error"):
                    return JSONEncoder().encode({"Error":"DB object %s was not inserted."})%(dado)
                hosts_will_add.append(dado)
        retorno_funcao = inserir_hosts_firewall(hosts_will_add)
        if retorno_funcao != []:
            stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='Error',reason='Rule %s not implemented because it was not possible to communicate with the Firewall.'""",ip,user,regra["name"])
            return JSONEncoder().encode({"Error":"Can not insert the object: %s on Firewall"})%(hosts_will_add)
        dic_regra["vsys"] = settings.FW_HOST
        dic_regra["device"] = "fw-pa-dc-rj-11"
        dic_regra["source"] = {}
        dic_regra["source"]["zone"] = settings.SOURCEZONE
        dic_regra["source"]["address"] = regra["source"]
        dic_regra["source"]["user"] = "any"
        dic_regra["source"]["hip"] = "any"
        dic_regra["destination"] = {}
        dic_regra["destination"]["zone"] = settings.DESTZONE
        dic_regra["destination"]["address"] = ["any"]
        if regra.has_key("app_name"):
            dic_regra["app"] = [regra["app_name"]]
        else:
            return JSONEncoder().encode({"Error":"Application name uninformed."})    
        dic_regra["service"] = ["application-default"]
        dic_regra["profile"] = "any"
        dic_regra["options"] = "any"
        if regra.has_key("desc"):
            dic_regra["desc"] = regra["desc"]
        else:
            now = datetime.now()
            data = "%s"%now.day + "/" + "%s"%now.month + "/" + "%s"%now.year + " as " + "%s"%now.hour + ":" + "%s"%now.minute + ":" + "%s"%now.second  
            dic_regra["desc"] = "Rule inserted by %s:%s in: %s "%(ip,user,data)
        dic_regra["name"] = "%s"%regra["name"]
        dic_regra["tag"] = "API"
        
        return_control_rules = insert_rules_owners(user,ip,{"name":regra["name"],"sources":regra["source"]})
        if return_control_rules.has_key("Error"):
            return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
        
        return_db = db_call(user,ip,{"insert":dic_regra,"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"DB rule %s was not inserted."})%(dic_regra["name"])
        dic_app = {"app_name":regra["app_name"],"parent-app":regra["parent-app"],"regra_name":regra["name"],"url":regra["url"]}
        return_db = db_call(user,ip,{"insert":dic_app,"collection":"collection3"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"DB rule %s was not inserted."})%(dic_app["regra_name"])
        retorno_funcao_app = inserir_app_firewall(dic_app)
        if retorno_funcao_app == []:
            stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='App %s include in Firewall.'""",ip,user,dic_app["app_name"])
        else:
            stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='App %s not include in Firewall.'""",ip,user,dic_app["app_name"])
            return JSONEncoder().encode({"Error":"App not included in Firewall. Please contact the system administrator."})
        retorno_funcao = inserir_regra_firewall(dic_regra)
        if retorno_funcao != []:
            stdout_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Firewall rule %s not inserted into the Firewall.'""",ip,user,dic_regra["name"])
            return JSONEncoder().encode({"Error":"Firewall rule not inserted into the Firewall. Please contact the system administrator."})
        else:
            retorno_cleanup = deladd_cleanup_firewall()
            if retorno_cleanup == []:
                lock_commit = commit_lock(lock_control())
                if lock_commit["response"] == "OK":
                    result_commit = commit_vsys()
                    if result_commit != []:
                        id_commit = commit_control(user,ip,"Uncommitted")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s inserted in Firewall but uncommitted. ID Commit = %s'""",ip,user,dic_regra["name"],id_commit)  
                        return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted. ID Commit = %s"})%(dic_regra["name"],id_commit)
                    else:
                        id_commit = commit_control(user,ip,"Committed")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        update_collection = commit_update(id_commit)
                        if update_collection.has_key("Error"):
                            return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,dic_regra["name"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Rule %s inserted in Firewall. ID Commit = %s'""",ip,user,dic_regra["name"],id_commit)
                        return JSONEncoder().encode({"Success":"Rule inserted in Firewall! Commit ID = %s"})%id_commit
                else:
                    id_commit = commit_control(user,ip,"Uncommitted")
                    if type(id_commit) != int:
                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,dic_regra["name"])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s inserted in Firewall but uncommitted. ID Commit = %s'""",ip,user,dic_regra["name"],id_commit)  
                    return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted. ID Commit = %s"})%(dic_regra["name"],id_commit)
            else:
                stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Erro removing Clean_UP rule.'""",ip,user)
                return JSONEncoder().encode({"Error":"Problems with Clean_UP rule. Please contact the security team immediately."})

def inserir_regra(user,ip,regra):
    if regra.has_key("name"):
        return_db = db_call(user,ip,{"find":[{"name":regra["name"]},{"_id":0}],"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})
        if return_db["Collection"] != []:
            return JSONEncoder().encode({"Error":"Firewall rule %s existing."})%(regra["name"])
    else:
        return JSONEncoder().encode({"Error":"Rule name not set."})
    valor = [] # Verificando se a regra em questao ja existe. A busca no banco sera atraves do destino, app e service
    hosts_will_add = []
    if regra.has_key("source"):    
        if regra.has_key("app"):
            valor.extend([{"app":x} for x in regra["app"]])
        else:
            valor.append({"app":["any"]})
        if regra.has_key("service"):
            valor.extend([{"service":x} for x in regra["service"]]) 
        else:
            valor.append({"service":["any"]})
        if regra.has_key("destination"):
            valor.extend([{"destination.address":x} for x in regra["destination"]])
        else:
            return JSONEncoder().encode({"Error":"Destination field required in this case."})
    else:
        return JSONEncoder().encode({"Error":"No source informed."})

    return_db = db_call(user,ip,{"find":[{"$and":valor},{"_id":0}],"collection":"collection"})
    if return_db.has_key("Error"):
        return JSONEncoder().encode({"Error":"Can't connect with DB."})
    
    control = [x for x in return_db["Collection"] if (set(x["destination"]["address"]) == set(regra["destination"]))]
    if control != []: #O cursor encontrou a regra com os destinos desejados(destination, app e service juntas nao se repetem).Verificar se os source hosts estao nas regras. Se nao estiverem, serao adicionados.
        nome_regra = control[0]["name"]
        n_contido_sources = list(set(regra["source"]) - set(control[0]["source"]["address"]))
        if n_contido_sources == []:
            return JSONEncoder().encode({"Error":"Rule already exists with the name: %s."})%(nome_regra)
        for entry in regra["source"]:
            return_db = db_call(user,ip,{"find":[{"address":entry},{"_id":0}],"collection":"collection2"})
            if return_db.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            if return_db["Collection"] == []:
                return_db_2 = db_call(user,ip,{"insert":entry,"collection":"collection2"})
                if return_db_2.has_key("Error"):
                    return JSONEncoder().encode({"Error":"DB object %s was not inserted."})%(entry)
                hosts_will_add.append(entry)
                
        return_control_rules = insert_rules_owners(user,ip,{"name":nome_regra,"sources":hosts_will_add,"rule_exists":"yes"})
        
        return_db = db_call(user,ip,{"push":hosts_will_add,"name":nome_regra,"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"Rule %s wasn't updated with new source element(s) %s."})%(nome_regra,n_contido_sources)
        
        if return_control_rules.has_key("Error"):
            return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
        retorno_funcao = inserir_hosts_firewall(hosts_will_add)
        if retorno_funcao != []:
            string_out_insert = ""
            for value in hosts_will_add:
                string_out_insert = string_out_insert + "%s, "%value
            stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Object(s) %s not included in the firewall.'""",ip,user,string_out_insert[:-1])
            return JSONEncoder().encode({"Error":"Unable to insert the object(s): %s in the firewall rule."})%(string_out_insert[:-1])
        else:
            retorno_regra_append = inserir_regra_firewall({"source_append":n_contido_sources,"name":nome_regra})
            string_out = ""
            for value in n_contido_sources:
                string_out = string_out + "%s, "%value
            if retorno_regra_append != []:
                stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Rule %s wasn't updated with element(s): %s.'""",ip,user,nome_regra,string_out[:-1])
                return JSONEncoder().encode({"Error":"Rule: %s wasn't updated with source(s): %s"})%(nome_regra,string_out[:-1])
            else:
                lock_commit = commit_lock(lock_control())
                if lock_commit["response"] == "OK":
                    result_commit = commit_vsys()
                    if result_commit != []:
                        id_commit = commit_control(user,ip,"Uncommitted")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s has been updated with element(s): %s but uncommitted.'""",ip,user,nome_regra,string_out[:-1])  
                        return JSONEncoder().encode({"Alert":"Rule: %s updated with element(s) %s but uncommitted. ID Commit = %s"})%(nome_regra,string_out[:-1],id_commit)
                    else:
                        id_commit = commit_control(user,ip,"Committed")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        update_collection = commit_update(id_commit)
                        if update_collection.has_key("Error"):
                            return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was updated with sources %s.'""",ip,user,nome_regra,string_out[:-1])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s has been updated with source(s): %s.'""",ip,user,nome_regra,string_out[:-1])
                        return JSONEncoder().encode({"Success":"Rule: %s has been updated with source(s): %s. ID Commit = %s"})%(nome_regra,string_out[:-1],id_commit)
                else:
                    id_commit = commit_control(user,ip,"Uncommitted")
                    if type(id_commit) != int:
                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was updated with source(s) %s.'""",ip,user,nome_regra,string_out[:-1])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s has been updated with source(s): %s, but uncommitted. ID Commit = %s'""",ip,user,nome_regra,string_out[:-1],id_commit)  
                    return JSONEncoder().encode({"Alert":"Rule: %s has been updated with source(s) %s, but uncommitted. ID Commit = %s"})%(nome_regra,string_out[:-1],id_commit)                    
    else:
        dic_regra = {}
        valor = regra["source"][:]
        if regra.has_key("destination"):
            valor.extend(regra["destination"][:])
        else:
            return JSONEncoder().encode({"Error":"Required field destination."})
        for entry in valor:
            return_db_2 = db_call(user,ip,{"find":[{"address":entry},{"_id":0}],"collection":"collection2"})
            if return_db_2.has_key("Error"):
                return JSONEncoder().encode({"Error":"Can't connect with DB."})
            if return_db_2["Collection"] == []:
                return_db = db_call(user,ip,{"insert":entry,"collection":"collection2"})
                if return_db.has_key("Error"):
                    return JSONEncoder().encode({"Error":"DB object %s was not inserted."})%(entry)
                hosts_will_add.append(entry)
                
        retorno_funcao = inserir_hosts_firewall(hosts_will_add)
        if retorno_funcao != []:
            stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='Error',reason='Rule %s not updated with element(s) %s'""",ip,user,regra["name"],hosts_will_add)
            return JSONEncoder().encode({"Error":"Could not insert the object(s): %s in Firewall"})%(hosts_will_add)
        dic_regra["vsys"] = settings.FW_HOST
        dic_regra["device"] = "fw-pa-dc-rj-11"
        dic_regra["source"] = {}
        dic_regra["source"]["zone"] = settings.SOURCEZONE
        dic_regra["source"]["address"] = regra["source"]
        dic_regra["source"]["user"] = "any"
        dic_regra["source"]["hip"] = "any"
        dic_regra["destination"] = {}
        dic_regra["destination"]["zone"] = settings.DESTZONE
        dic_regra["destination"]["address"] = regra["destination"]
        if regra.has_key("app"):
            dic_regra["app"] = regra["app"]
        else:
            dic_regra["app"] = ["any"]
        if regra.has_key("service"):
            dic_regra["service"] = regra["service"]
        else:
            dic_regra["service"] = ["any"]
        dic_regra["profile"] = "any"
        dic_regra["options"] = "any"
        if regra.has_key("desc"):
            dic_regra["desc"] = regra["desc"]
        else:
            now = datetime.now()
            data = "%s"%now.day + "/" + "%s"%now.month + "/" + "%s"%now.year + " as " + "%s"%now.hour + ":" + "%s"%now.minute + ":" + "%s"%now.second  
            dic_regra["desc"] = "Rule inserted by %s:%s in: %s "%(ip,user,data)
        dic_regra["name"] = "%s"%regra["name"]
        dic_regra["tag"] = "API"

        return_db = db_call(user,ip,{"insert":dic_regra,"collection":"collection"})

        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"DB rule %s was not inserted."})%(regra["name"])        
        return_control_rules = insert_rules_owners(user,ip,{"name":regra["name"],"sources":regra["source"]})
        if return_control_rules.has_key("Error"):
            return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
        
        retorno_funcao = inserir_regra_firewall(dic_regra)
        if retorno_funcao != []:
            return JSONEncoder().encode({"Error":"Rule not inserted in Firewall. Please contact the security team."})
        else:
            retorno_cleanup = deladd_cleanup_firewall()
            if retorno_cleanup == []:
                lock_commit = commit_lock(lock_control())
                if lock_commit["response"] == "OK":
                    result_commit = commit_vsys()
                    if result_commit != []:
                        id_commit = commit_control(user,ip,"Uncommitted")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s inserted in Firewall but uncommitted. ID Commit = %s'""",ip,user,dic_regra["name"],id_commit)  
                        return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted. ID Commit = %s"})%(dic_regra["name"],id_commit)
                    else:
                        id_commit = commit_control(user,ip,"Committed")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        update_collection = commit_update(id_commit)
                        if update_collection.has_key("Error"):
                            return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,dic_regra["name"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Rule %s inserted in Firewall.'""",ip,user,dic_regra["name"])
                        return JSONEncoder().encode({"Success":"Rule inserted in Firewall! Commit ID = %s"})%id_commit
                else:
                    id_commit = commit_control(user,ip,"Uncommitted")
                    if type(id_commit) != int:
                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,dic_regra["name"])
                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s inserted in Firewall but uncommitted. ID Commit = %s'""",ip,user,dic_regra["name"],id_commit)  
                    return JSONEncoder().encode({"Alert":"Rule: %s inserted in Firewall but uncommitted. ID Commit = %s"})%(dic_regra["name"],id_commit)
            else:
                stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Erro removing Clean_UP rule.'""",ip,user)
                return JSONEncoder().encode({"Error":"Problems with Clean_UP rule. Please contact the security team immediately."})
            
def atualiza_regra(user,ip,regra):
    if not regra.has_key("action"):
        return JSONEncoder().encode({"Error":"No action set"})
    if not regra.has_key("source"):
        return JSONEncoder().encode({"Error":"No sources set"})
    if regra.has_key("name"):
        return_db = db_call(user,ip,{"find":[{"name":regra["name"]},{"_id":0}],"collection":"collection"})
        if return_db.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})
        if return_db["Collection"] == []:
            return JSONEncoder().encode({"Error":"Firewall rule: %s, doesn't exist."})%(regra["name"])
        else:
            if regra["action"] == "add":
                saida = {}
                hosts_will_add = []
                for value_key in regra.keys():
                    if value_key == "source":
                        nome_dic = value_key + ".address"
                        return_db = db_call(user,ip,{"find":[{"name":regra["name"]},{nome_dic:1,"_id":0}],"collection":"collection"})
                        if return_db.has_key("Error"):
                            return JSONEncoder().encode({"Error":"Can't connect with DB."})
                        if return_db["Collection"] == []:
                            return JSONEncoder().encode({"Alert":"Rule doesn't exist."})
                        n_contidos = list(set(regra[value_key]) - set(return_db["Collection"][0][value_key]["address"]))
                        if n_contidos == []:#O que foi fornecido esta na regra. Nada feito.
                            return JSONEncoder().encode({"Alert":"Object(s) is(are) already inserted in the rule."})
                        for entry in n_contidos:
                            return_db_2 = db_call(user,ip,{"find":[{"address":entry},{"_id":0}],"collection":"collection2"})
                            if return_db_2.has_key("Error"):
                                return JSONEncoder().encode({"Error":"Can't connect with DB."})
                            if return_db_2["Collection"] == []:
                                return_db_3 = db_call(user,ip,{"insert":entry,"collection":"collection2"})
                                if return_db_3.has_key("Error"):
                                    return JSONEncoder().encode({"Error":"DB object %s was not inserted."})%(entry)
                                hosts_will_add.append(entry)
                        if hosts_will_add != []:
                            retorno_funcao = inserir_hosts_firewall(hosts_will_add)
                            if retorno_funcao != []:
                                stderror_logger.error("""app='TZION',source='%s',username='%s',action='insert',status='ERROR',reason='Object(s) %s not inserted in the Firewall'""",ip,user,hosts_will_add)
                                return JSONEncoder().encode({"Error":"Could not insert object %s in Firewall."})%(retorno_funcao)
                        if return_db["Collection"][0][value_key]["address"] == ["any"]:
                            remover_any_regra_firewall(regra["name"],value_key)
                            return_db = db_call(user,ip,{"set":n_contidos,"name":regra["name"],"collection":"collection"})
                        else:
                            return_db = db_call(user,ip,{"push":n_contidos,"name":regra["name"],"collection":"collection"})
                        if return_db.has_key("Error"):
                            return JSONEncoder().encode({"Error":"Rule %s wasn't updated with new source element(s) %s."})%(regra["name"],n_contidos)
                        retorno_regra_append = inserir_regra_firewall({"source_append":n_contidos,"name":regra["name"]})
                        frase = "updated with values: "
                        for value in n_contidos:
                            frase = frase + "%s "%value
                        if retorno_regra_append != []:
                            saida = {"Error":"Rule: %s, wasn't %s"%(regra["name"],frase)}
                            stderror_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='Firewall rule %s wasn't %s'""",ip,user,regra["name"],frase)
                            return JSONEncoder().encode(saida)
                        else:
                            return_control_rules = insert_rules_owners(user,ip,{"name":regra["name"],"sources":n_contidos,"rule_exists":"rule_exists"})
                            if return_control_rules.has_key("Error"):
                                return JSONEncoder().encode({"Error":"Collection wasn't updated with new rule's authorization."})
                            
                            lock_commit = commit_lock(lock_control())
                            if lock_commit["response"] == "OK":       
                                result_commit = commit_vsys()
                                if result_commit != []:
                                    id_commit = commit_control(user,ip,"Uncommitted")
                                    if type(id_commit) != int:
                                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Firewall rule %s was %s but uncommitted. ID Commit = %s'""",ip,user,regra["name"],frase,id_commit)  
                                    return JSONEncoder().encode({"Alert":"Rule: %s, %s but uncommitted. ID Commit = %s"})%(dic_regra["name"],frase,id_commit)        
                                else:
                                    id_commit = commit_control(user,ip,"Committed")
                                    if type(id_commit) != int:
                                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                    update_collection = commit_update(id_commit)
                                    if update_collection.has_key("Error"):
                                        return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,regra["name"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='OK',reason='Firewall rule %s %s. ID Commit = %s'""",ip,user,regra["name"],frase,id_commit)
                                    return JSONEncoder().encode({"Success":"Rule %s %s ! Commit ID = %s"})%(regra["name"],frase,id_commit)
                            else:
                                id_commit = commit_control(user,ip,"Uncommitted")
                                if type(id_commit) != int:
                                    return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,regra["name"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='insert',status='ALERT',reason='Rule %s updated but uncommitted. ID Commit = %s'""",ip,user,regra["name"],id_commit)  
                                return JSONEncoder().encode({"Alert":"Rule: %s updated but uncommitted. ID Commit = %s"})%(regra["name"],id_commit)
                return JSONEncoder().encode(saida)
                
            if regra["action"] == "remove":
                fields_will_keep = {}
                fields_will_not_keep = {}
                for value_key in regra.keys():
                    if  value_key == "source":
                        value_key_completo = value_key + ".address"
                        return_db_2 = db_call(user,ip,{"find":[{"name":regra["name"]},{value_key_completo:1,"_id":0}],"collection":"collection"})
                        if return_db_2.has_key("Error"):
                            return JSONEncoder().encode({"Error":"Can't connect with DB."})
                        if return_db_2["Collection"] != []: #o banco retornou valores, ou seja, podem existir items a serem removidos da regra
                            fields_will_not_keep[value_key] = [x for x in regra[value_key] if x in return_db_2["Collection"][0][value_key]["address"]]
                        else:
                            return JSONEncoder().encode({"Error":"Rule: %s, doesn't exist."})%(regra["name"])
                        return_owner_rule = db_call(user,ip,{"find":[{"rule_name":regra["name"]},{"_id":0}],"collection":"collection4"})
                        if return_owner_rule.has_key("Error"):
                            return JSONEncoder().encode({"Error":"DB error: %s."})%(return_owner_rule["Error"])
                        if return_owner_rule["Collection"][0]["sources_owners"].has_key(user):
                            permission_del = [x for x in fields_will_not_keep[value_key] if x in return_owner_rule["Collection"][0]["sources_owners"][user]]
                        else:
                            permission_del = []
                        if permission_del == []:
                            word = ""
                            for value in fields_will_not_keep[value_key]:
                                word = word + " %s,"%value
                            if word == "":
                                return JSONEncoder().encode({"Alert":"There is no elements to be removed from the rule %s."})%(regra["name"])
                            else:
                                return JSONEncoder().encode({"Forbidden":"Unauthorized removal of the rule element(s): %s."})%(word[:-1])
                        else:
                            fields_will_keep_owner = [x for x in return_owner_rule["Collection"][0]["sources_owners"][user] if not x in permission_del]
                            if fields_will_keep_owner == []:
                                return_verify = remove_rules_owners(user,ip,{"set_end":"end","name":regra["name"]})
                                if return_verify.has_key("Error"):
                                    return JSONEncoder().encode({"Error":"DB rule %s wasn't updated without the field sources_owners.%s"})%(regra["name"],user)
                            else:
                                return_verify = remove_rules_owners(user,ip,{"set":fields_will_keep_owner,"name":regra["name"]})                       
                                if return_verify.has_key("Error"):
                                    return JSONEncoder().encode({"Error":"DB rule %s wasn't updated with new source element: any."})%(regra["name"])
                                if return_verify.has_key("Forbidden"):
                                    return JSONEncoder().encode(return_verify["Forbidden"])       
                        #Acertando no banco de dados o que realmente precisa ficar na regra para depois alterar no Firewall
                        fields_will_keep[value_key] = [x for x in return_db_2["Collection"][0][value_key]["address"] if x not in permission_del]
                        
                        if fields_will_keep[value_key] == []:
                            return_rule_db_keep = db_call(user,ip,{"set":["any"],"name":regra["name"],"collection":"collection"})
                        else:
                            return_rule_db_keep = db_call(user,ip,{"set":fields_will_keep[value_key],"name":regra["name"],"collection":"collection"})
                        if return_rule_db_keep.has_key("Error"):
                            return JSONEncoder().encode({"Error":"DB rule %s wasn't updated the field sources: %s"})%(regra["name"],fields_will_keep[value_key])
                                        
                        retorno = remover_obj_regra_firewall({value_key_completo:fields_will_keep["source"]},regra["name"])
                        frase = "updated. Current source field: "
                        if fields_will_keep[value_key] == []:
                            frase = "updated. Current source field: any "
                        else:
                            for value in fields_will_keep[value_key]:
                                frase = frase + "%s, "%value
                        if retorno == []:
                            lock_commit = commit_lock(lock_control())
                            if lock_commit["response"] == "OK":
                                result_commit = commit_vsys()
                                if result_commit != []:
                                    id_commit = commit_control(user,ip,"Uncommitted")
                                    if type(id_commit) != int:
                                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='ALERT',reason='Rule %s %s but uncommitted. ID Commit: %s'""",ip,user,regra["name"],frase[:-1],id_commit)  
                                    return JSONEncoder().encode({"Alert":"Rule: %s, %s but not commited. ID Commit: %s"})%(regra["name"],frase[:-1],id_commit)
                                else:
                                    id_commit = commit_control(user,ip,"Committed")
                                    if type(id_commit) != int:
                                        return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                    update_collection = commit_update(id_commit)
                                    if update_collection.has_key("Error"):
                                        return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was inserted in Firewall.'""",ip,user,regra["name"])
                                    stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Rule %s %s. ID Commit: %s'""",ip,user,regra["name"],frase[:-1],id_commit)             
                                    return JSONEncoder().encode({"Success":"Rule: %s, %s. ID Commit: %s"})%(regra["name"],frase[:-1],id_commit)
                            else:
                                id_commit = commit_control(user,ip,"Uncommitted")
                                if type(id_commit) != int:
                                    return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='ALERT',reason='Rule %s %s but uncommitted. ID Commit: %s'""",ip,user,regra["name"],frase[:-1],id_commit)  
                                return JSONEncoder().encode({"Alert":"Rule: %s, %s but not commited. ID Commit: %s"})%(regra["name"],frase[:-1],id_commit)
                        else:
                            stderror_logger.error("""app='TZION',source='%s',username='%s',action='update',status='ERROR',reason='Rule %s don't %s.'""",ip,user,regra["name"],frase[:-1])             
                            return JSONEncoder().encode({"Error":"Rule: %s, wasn't updated."})%(regra["name"])
    else:
        return JSONEncoder().encode({"Error":"Rule name not sent."})
    
def remove_regra(user,ip,regra):
    if regra.has_key("name"):
        return_db_2 = db_call(user,ip,{"find":[{"name":regra["name"]},{"_id":0}],"collection":"collection"})
        if return_db_2.has_key("Error"):
            return JSONEncoder().encode({"Error":"Can't connect with DB."})
        if return_db_2["Collection"] == []:
            return JSONEncoder().encode({"Error":"Rule: %s, not found."})%(regra["name"])
        else:
            regra["DEL"] = "DEL"
            return_verify = remove_rules_owners(user,ip,regra)
            if return_verify.has_key("Forbidden"):
                return JSONEncoder().encode({"Forbidden":"Unauthorized removal of the rule %s because there are other entries of data belonging to other users."})%(regra["name"])
            if return_verify.has_key("Error"):
                return JSONEncoder().encode({"Error":"DB Rule %s wasn't deleted."})%(regra["name"])
            if return_verify.has_key("Collection"):
                retorno = remover_regra_firewall(regra["name"])
            if retorno == []:
                return_db_3 = db_call(user,ip,{"find":[{"regra_name":regra["name"]},{"_id":0}],"collection":"collection3"})
                if return_db_3.has_key("Error"):
                    return JSONEncoder().encode({"Error":"Can't connect with DB."})                    
                if return_db_3["Collection"] != []:#retornou valor. Possuimos uma app l7 cadastrada para essa regra.
                    return_db = db_call(user,ip,{"remove":return_db_3["Collection"][0]["app_name"],"collection":"collection3"})
                    if return_db.has_key("Error"):
                        return JSONEncoder().encode({"Error":"DB Rule %s wasn't deleted."})%(regra["name"])
                    retorno_app = remover_app_firewall(return_db_3["Collection"][0]["app_name"])
                    if retorno_app == []:
                        lock_commit = commit_lock(lock_control())
                        if lock_commit["response"] == "OK":
                            result_commit = commit_vsys()
                            if result_commit != []:
                                id_commit = commit_control(user,ip,"Uncommitted")
                                if type(id_commit) != int:
                                    return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='Alert',reason='Rule %s and Application %s were removed but uncommitted. ID Commit: %s'""",ip,user,regra["name"],return_db_3["Collection"][0]["app_name"],id_commit)
                                return JSONEncoder().encode({"Alert":"Rule: %s and Application %s were removed but uncommitted. ID Commit: %s"})%(regra["name"],return_db_3["Collection"][0]["app_name"],id_commit)  
                            else:
                                id_commit = commit_control(user,ip,"Committed")
                                if type(id_commit) != int:
                                    return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                                update_collection = commit_update(id_commit)
                                if update_collection.has_key("Error"):
                                    return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s and Application %s were removed.'""",ip,user,regra["name"],return_db_3["Collection"][0]["app_name"])
                                stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='OK',reason='Rule %s and Application %s were removed!'""",ip,user,regra["name"],return_db_3["Collection"][0]["app_name"])   
                                return JSONEncoder().encode({"Success":"Rule: %s removed!. ID Commit: %s"})%(regra["name"],id_commit)                            
                        else:
                            id_commit = commit_control(user,ip,"Uncommitted")
                            if type(id_commit) != int:
                                return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='Alert',reason='Rule %s and Application %s were removed but uncommitted. ID Commit: %s'""",ip,user,regra["name"],return_db_3["Collection"][0]["app_name"],id_commit)
                            return JSONEncoder().encode({"Alert":"Rule %s and Application %s were removed but uncommitted. ID Commit: %s"})%(regra["name"],return_db_3["Collection"][0]["app_name"],id_commit)
                    else:
                        stderror_logger.error("""app='TZION',source='%s',username='%s',action='remove',status='ERROR',reason='Rule %s and Application %s were removed but uncommitted.'""",ip,user,regra["name"],regra_app[0]["app_name"])             
                        return JSONEncoder().encode({"Error":"Rule %s and Application %s were removed but uncommited."})%(regra["name"],regra_app[0]["app_name"])
                else:#Nao encontrou app l7. Vai remover a regra direto.
                    lock_commit = commit_lock(lock_control())
                    if lock_commit["response"] == "OK":
                        result_commit = commit_vsys()
                        if result_commit != []:
                            id_commit = commit_control(user,ip,"Uncommitted")
                            if type(id_commit) != int:
                                return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='Alert',reason='Rule %s removed but uncommitted. ID Commit: %s'""",ip,user,regra["name"],id_commit)
                            return JSONEncoder().encode({"Alert":"Rule: %s, removed but uncommitted. ID Commit: %s"})%(regra["name"],id_commit)  
                        else:
                            id_commit = commit_control(user,ip,"Committed")
                            if type(id_commit) != int:
                                return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                            update_collection = commit_update(id_commit)
                            if update_collection.has_key("Error"):
                                return JSONEncoder().encode({"Error":"%s."})%(update_commit["Error"])
                            stdout_logger.info("""app='TZION',source='%s',username='%s',action='update',status='OK',reason='Collection Commit updated when Rule %s was removed.'""",ip,user,regra["name"])                            
                            return JSONEncoder().encode({"Success":"Rule: %s removed!. ID Commit: %s"})%(regra["name"],id_commit)                            
                    else:
                        id_commit = commit_control(user,ip,"Uncommitted")
                        if type(id_commit) != int:
                            return JSONEncoder().encode({"Error":"%s."})%(id_commit["Error"])
                        stdout_logger.info("""app='TZION',source='%s',username='%s',action='remove',status='Alert',reason='Rule %s removed but uncommitted. ID Commit: %s'""",ip,user,regra["name"],id_commit)
                        return JSONEncoder().encode({"Alert":"Rule: %s removed but uncommitted. ID Commit: %s"})%(regra["name"],id_commit)
            else:
                stderror_logger.error("""app='TZION',source='%s',username='%s',action='remove',status='ERROR',reason='Rule %s, not removed!'""",ip,user,regra["name"])             
                return JSONEncoder().encode({"Error":"Rule %s not removed."})%(regra["name"])
    else:
        return JSONEncoder().encode({"Error":"Rule name not informed!"})