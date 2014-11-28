# -*- coding: utf-8 -*-
import json, logging
from logging.handlers import SysLogHandler
from bson.objectid import ObjectId
from datetime import datetime
from rules_firewall import *
from rules_db import *
import settings
import sys

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

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

def commit_control(user,ip,word):
    now = datetime.now()
    data = "%s"%now.day + "/" + "%s"%now.month + "/" + "%s"%now.year + " - " + "%s"%now.hour + ":" + "%s"%now.minute + ":" + "%s"%now.second
    return_db = db_call(user,ip,{"find":[{},{"rule_id":1,"_id":0}],"collection":"collection5"})
    if return_db.has_key("Error"):
        return JSONEncoder().encode({"Error":"Can't connect with DB."})
    if return_db["Collection"] == []:
        id_reserved = 1
    else:
        ids = [x["rule_id"] for x in return_db["Collection"]]
        id_reserved = max(ids) + 1
    return_db_new = db_call(user,ip,{"insert":{"rule_id":id_reserved,"date-time":data,"status":word},"collection":"collection5"})
    if return_db_new.has_key("Error"):
        return JSONEncoder().encode({"Error":"Can't connect with DB."})
    return id_reserved

def commit_req(value):
    result_out = db_call("","",{"find":[{"rule_id":value},{"rule_id":0,"_id":0}],"collection":"collection5"})
    if result_out.has_key("Error"):
        return result_out["Error"]
    else:
        if result_out["Collection"] == []:
            return {"Error":"Commit ID not found!"}
        else:
            return result_out["Collection"][0]
            
def commit_update(id_max):
    commit_set = db_call("","",{"set":[{"rule_id":{"$lt":id_max}},{"$set":{"status":"Committed"}}],"collection":"collection5"})
    if commit_set.has_key("Error"):
        return JSONEncoder().encode({"Error":"Can't connect with DB."})
    else:
        return commit_set
        
def commit_lock(lock):
    if lock["response"]["result"]["commit-locks"] != None:
        if type(lock["response"]["result"]["commit-locks"]["entry"]) != list:
            if lock["response"]["result"]["commit-locks"]["entry"]["@name"] == "leopoldo.api":
                return {"response":"OK"}
            else:
                return {"response":"Busy"}
        else:
            return {"response":"Busy"}
    else:
        return {"response":"OK"}