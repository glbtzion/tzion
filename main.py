# -*- coding: utf-8 -*-
import os
from flask import redirect, request, app, Flask, url_for, json
from functions import *
from commit_control import *
from json_valid import *
from bson.objectid import ObjectId
import logging, xmltodict, urllib
from datetime import datetime
from datetime import timedelta
import settings

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

app = Flask(__name__)
app.debug = settings.DEBUG

@app.route('/', methods = ['GET'])
def home():
    return redirect("http://tzion-doc.mycompany.com")

@app.route('/healthcheck', methods = ['GET'])
def healthcheck():
    return "working"

@app.route('/tzion', methods = ['GET'])
def busca_regras():
    authentication = autenticacao(request.json["user"],request.json["password"],request.remote_addr)
    if authentication == "200 OK":
        regra_validada = fix_json(request.json["regra"])
        if type(regra_validada) is dict:
            saida = buscar_regra(request.json["user"],request.remote_addr,regra_validada["regra"])
            return saida
        else:
            return regra_validada
    else:
        return "Failed to authenticate the user %s"%(request.json["user"])
        
@app.route('/tzion/<int:value>', methods = ['GET'])
def commit(value):
    commit_out = commit_req(value)
    return JSONEncoder().encode({"Result":commit_out})

@app.route('/tzion', methods = ['POST'])
def insere_regras():
    authentication = autenticacao(request.json["user"],request.json["password"],request.remote_addr)
    if authentication == "200 OK":
        grupo_auth = grupo(request.json["user"],request.json["password"],request.remote_addr)
        if grupo_auth == "200 OK":
            regra_validada = fix_json(request.json["regra"])
            if type(regra_validada) is dict:
                if "url" in request.json["regra"].keys():
                    saida = inserir_regra_L7(request.json["user"],request.remote_addr,regra_validada["regra"])
                else:    
                    saida = inserir_regra(request.json["user"],request.remote_addr,regra_validada["regra"])
                return saida
            else:
                return regra_validada
        else:
            return JSONEncoder().encode({"Error":"No permission for the user %s"})%(request.json["user"])
    else:
        return JSONEncoder().encode({"Error":"Failed to authenticate the user %s"})%(request.json["user"])

@app.route('/tzion', methods = ['PUT'])
def atualiza_regras():
    authentication = autenticacao(request.json["user"],request.json["password"],request.remote_addr)
    if authentication == "200 OK":
        grupo_auth = grupo(request.json["user"],request.json["password"],request.remote_addr)
        if grupo_auth == "200 OK":
            regra_validada = fix_json(request.json["regra"])
            if type(regra_validada) is dict:
                saida = atualiza_regra(request.json["user"],request.remote_addr,regra_validada["regra"])
                return saida
            else:
                return regra_validada
        else:
            return JSONEncoder().encode({"Error":"No permission for the user %s"})%(request.json["user"])
    else:
        return "Failed to authenticate the user %s"%(request.json["user"])

@app.route('/tzion', methods = ['DELETE'])
def apaga_regra():
    authentication = autenticacao(request.json["user"],request.json["password"],request.remote_addr)
    if authentication == "200 OK":
        grupo_auth = grupo(request.json["user"],request.json["password"],request.remote_addr)
        if grupo_auth == "200 OK":
            regra_validada = fix_json(request.json["regra"])
            if type(regra_validada) is dict:
                saida = remove_regra(request.json["user"],request.remote_addr,regra_validada["regra"])
                return saida
            else:
                return regra_validada
        else:
            return JSONEncoder().encode({"Error":"No permission for the user %s"})%(request.json["user"])
    else:
        return "Failed to authenticate the user %s"%(request.json["user"])

if __name__ == '__main__':
    porta = int(os.getenv('PORT', 8080))
    print 'Starting server on port:{0}'.format(porta)
    app.run(host='0.0.0.0', port=porta, debug=True)
