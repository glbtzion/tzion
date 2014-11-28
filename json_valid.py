# -*- coding: utf-8 -*-
import json,requests,re
from bson.objectid import ObjectId
import settings
import sys

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


def fix_json(regra):
    regra_new = {}
    regra_new["regra"] = {}
    if regra.has_key("url"):
        if regra.has_key("destination"):
            regra.pop("destination",None)
    for key in regra.keys():           
        if ((key == "source") or (key == "destination")):
            if (type(regra[key]) != list) or (regra[key] == []):
                return JSONEncoder().encode({"Error":"Object %s outside of API standards. Please consult the documentation."})%(key)
            valida = [x for x in regra[key] if not re.match(r'Host_(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})|Net_(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})_(\d{1,2})',x,re.I)]
            if valida != []:
                return JSONEncoder().encode({"Error":"Object %s outside of API standards. Please consult the documentation."})%(key)
            regra_new["regra"][key] = []
            for valor in regra[key]:
                regra_new["regra"][key].append(valor.title())
            continue
        if ((key == "app") or (key == "service")):
            if (type(regra[key]) != list) or (regra[key] == []):
                return JSONEncoder().encode({"Error":"Object %s outside of API standards. Please consult the documentation."})%(key)
            valida = [x for x in regra[key] if (len (x)) >= 32]
            if valida != []:
                return JSONEncoder().encode({"Error":"Object %s must be at most 31 characters."})%(key)
            regra_new["regra"][key] = []
            for valor in regra[key]:
                regra_new["regra"][key].append(valor.lower())
            continue
        if (key == "parent-app"): 
            if not regra["parent-app"] in ["web-browsing","ssl"]:
                return JSONEncoder().encode({"Error":"Object %s outside of API standards. Please consult the documentation."})%key 
        if ((key == "name") or (key == "parent-app") or (key == "method") or (key == "action")):
            if (type(regra[key]) != unicode) or ((len(regra[key]) == 0)):
                return JSONEncoder().encode({"Error":"Object %s outside of API standards. Please consult the documentation."})%key
            if ((key == "name") and ((len(regra["name"])) >= 32)):
                return JSONEncoder().encode({"Error":"Name of the rule should have at most 31 characters. Please consult the documentation."})
            lista_teste = []
            if key == "method":
                lista_teste.append(regra[key])
                valida = [x for x in lista_teste if not re.match(r'exact|any',x)]
                if valida != []:
                    return JSONEncoder().encode({"Error":"Method nonexistent. Please consult the documentation."})
                regra_new["regra"][key] = regra[key]
                continue
            if key == "action":
                lista_teste.append(regra[key])
                valida = [x for x in lista_teste if not re.match(r'add|remove',x)]
                if valida != []:
                    return JSONEncoder().encode({"Error":"Action nonexistent. Please consult the documentation."})
                regra_new["regra"][key] = regra[key]
                continue 
            regra_new[key] = ""
            if key == "name":
                regra_new["regra"][key] = regra[key].title()
            else:
                regra_new["regra"][key] = regra[key].lower()
            continue
        if ((key != "source") and (key != "destination") and (key != "app") and (key != "service") and (key != "name") and (key != "parent-app") and (key != "method") and (key != "action")):
            regra_new["regra"][key] = regra[key]
            continue
    return regra_new