# -*- coding: utf-8 -*-
import json, xmltodict, urllib, requests, re
import settings

host = settings.FW_URL
chave = settings.FW_KEY
inserir = "%stype=config&action=set&key=%s"%(host,chave)
remover = "%stype=config&action=delete&key=%s"%(host,chave)
editar = "%stype=config&action=edit&key=%s"%(host,chave)
comitar = "%stype=commit&key=%s"%(host,chave)
buscar = "%stype=op&key=%s"%(host,chave)

def lock_control():
    lock_control= """%s&cmd=<show><commit-locks></commit-locks></show>"""%(buscar)
    lock_doc = requests.get(lock_control,verify=False)
    return xmltodict.parse(lock_doc.content)

def commit_vsys():
    list_out = []
    commit = """%s&cmd=<commit><partial><vsys><member>%s</member></vsys></partial></commit>"""%(comitar,settings.FW_HOST) 
    rule_end = requests.get(commit,verify=False)
    rule_end = xmltodict.parse(rule_end.content)
    if (rule_end["response"]["@status"] == "error") or (rule_end == None):
        list_out.append(rule_end)
    return list_out

def inserir_hosts_firewall(hosts):
    lista_saida = []
    for valor in hosts:
        valor_real = valor.split("_")
        if len(valor_real) == 3:                
            insere_rede = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/address/entry[@name='%s']&element=<ip-netmask>%s/%s</ip-netmask>"""%(inserir,settings.FW_HOST,valor,valor_real[1],valor_real[2])
            rule_fim = urllib.urlopen(insere_rede).read()
            regras_doc = xmltodict.parse(rule_fim)    
        if len(valor_real) == 2:
            insere_host = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/address/entry[@name='%s']&element=<ip-netmask>%s/32</ip-netmask>"""%(inserir,settings.FW_HOST,valor,valor_real[1])
            rule_fim = urllib.urlopen(insere_host).read()
            regras_doc = xmltodict.parse(rule_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(regras_doc)
    return lista_saida
    
def inserir_app_regra_firewall(name_regra,lista):
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/application&"""%(inserir,settings.FW_HOST,name_regra)
    app_use = ""
    for valor in lista:
        app_use = app_use + """<member>%s</member>"""%(valor)
    app_final = """%selement=%s"""%(name,app_use)
    rule_fim = urllib.urlopen(app_final).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    return lista_saida
        
def inserir_service_regra_firewall(name_regra,lista):
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/service&"""%(inserir,settings.FW_HOST,name_regra)
    service_use = ""
    for valor in lista:
        service_use = service_use + """<member>%s</member>"""%(valor)
    service_final = """%selement=%s"""%(name,service_use)
    rule_fim = urllib.urlopen(service_final).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    return lista_saida

def inserir_regra_firewall(dicionario):
    lista_saida = []
    if dicionario.has_key("source_append"):
        name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/source&"""%(inserir,settings.FW_HOST,dicionario["name"])
        source = ""
        for valor in dicionario["source_append"]:
            source = source + """<member>%s</member>"""%(valor)
        source_final = """%selement=%s"""%(name,source)    
        rule_fim = urllib.urlopen(source_final).read()
        regras_doc = xmltodict.parse(rule_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(regras_doc)
    else:
        vsys_name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']"""%(inserir,dicionario["vsys"],dicionario["name"])
        tag = """%s&element=<option><disable-server-response-inspection>no</disable-server-response-inspection></option><tag><member>%s</member></tag>"""%(vsys_name,dicionario["tag"])
        zona = """%s<from><member>%s</member></from><to><member>%s</member></to>"""%(tag,dicionario["source"]["zone"],dicionario["destination"]["zone"])
        source = ""
        for valor in dicionario["source"]["address"]:
            source = source + """<member>%s</member>"""%(valor)
        source_final = """%s<source>%s</source>"""%(zona,source)
        destination = ""
        for valor in dicionario["destination"]["address"]:
            destination = destination + """<member>%s</member>"""%valor
        destination_final = """%s<destination>%s</destination>"""%(source_final,destination)
        user = """%s<source-user><member>any</member></source-user><category><member>%s</member></category>"""%(destination_final,dicionario["source"]["user"])
        application = ""
        for valor in dicionario["app"]:
            application = application + """<member>%s</member>"""%valor
        application_final = """%s<application>%s</application>"""%(user,application)
        service = ""
        for valor in dicionario["service"]:
            service = service + """<member>%s</member>"""%valor
        service_final = """%s<service>%s</service>"""%(application_final,service)
        comp = """%s<hip-profiles><member>any</member></hip-profiles><action>allow</action><log-start>yes</log-start><log-end>yes</log-end>"""%(service_final)
        comp_2 = """%s<negate-source>no</negate-source><negate-destination>no</negate-destination>"""%(comp)
        rule_fim = urllib.urlopen(comp_2).read()
        regras_doc = xmltodict.parse(rule_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(regras_doc)
    return lista_saida

#essa funcao remove objeto any de um determinado campo em determinada regra (feito para acertar um "bug").    
def remover_any_regra_firewall(name_regra,objeto):
    lista_saida = []
    if objeto == "app:":
        name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/application&"""%(remover,settings.FW_HOST,name_regra)
    else:
        name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/source&"""%(remover,settings.FW_HOST,name_regra)
    if objeto == "app":
        source_final = """%selement=<application><member>any</member></applicaton>"""%name
    else:
        source_final = """%selement=<source><member>any</member></source>"""%name
    rule_fim = urllib.urlopen(source_final).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    return lista_saida
    
def remover_regra_firewall(name_regra):
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']"""%(remover,settings.FW_HOST,name_regra)
    rule_fim = urllib.urlopen(name).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    return lista_saida
    
def remover_app_firewall(name_app):
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/application/entry[@name='%s']"""%(remover,settings.FW_HOST,name_app)
    rule_fim = requests.get(name,verify=False)
    rule_fim = xmltodict.parse(rule_fim.content)
    if (rule_fim["response"]["@status"] == "error") or (rule_fim == None):
        lista_saida.append(rule_fim)
    return lista_saida
    
#essa funcao na verdade faz um edit numa regra ja existente, baseada no que ela recebe. Ela recebe o que TEM que ficar na regra e elimina o resto.    
def remover_obj_regra_firewall(objeto,name_regra):
    lista_saida = []
    if objeto.has_key("source.address"):
        name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='%s']/source&"""%(editar,settings.FW_HOST,name_regra)
        source = ""
        if objeto["source.address"] == []:
            source = """<member>any</member>"""
        else:
            for valor in objeto["source.address"]:
                source = source + """<member>%s</member>"""%(valor)
        source_final = """%selement=<source>%s</source>"""%(name,source)
        source_fim = urllib.urlopen(source_final).read()
        regras_doc = xmltodict.parse(source_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(regras_doc)
    return lista_saida

def deladd_cleanup_firewall():
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='Clean_UP']"""%(remover,settings.FW_HOST)
    rule_fim = urllib.urlopen(name).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    else:
        vsys_name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules/entry[@name='Clean_UP']"""%(inserir,settings.FW_HOST)
        tag = """%s&element=<option><disable-server-response-inspection>no</disable-server-response-inspection></option><tag><member>DENY_ALL</member></tag>"""%(vsys_name)
        zona = """%s<from><member>any</member></from><to><member>any</member></to>"""%(tag)
        source = """%s<source><member>any</member></source>"""%(zona)
        destination = """%s<destination><member>any</member></destination>"""%(source)
        user = """%s<source-user><member>any</member></source-user><category><member>any</member></category>"""%(destination)
        application = """%s<application><member>any</member></application>"""%(user)
        service = """%s<service><member>any</member></service>"""%(application)
        comp = """%s<hip-profiles><member>any</member></hip-profiles><action>deny</action><log-start>yes</log-start><log-end>yes</log-end>"""%(service)
        comp_2 = """%s<negate-source>no</negate-source><negate-destination>no</negate-destination>"""%(comp)
        rule_fim = urllib.urlopen(comp_2).read()
        regras_doc = xmltodict.parse(rule_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(dicionario)
    return lista_saida
    
def inserir_app_firewall(dic_app):
    lista_saida = []
    name = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/application/entry[@name='%s']"""%(inserir,settings.FW_HOST,dic_app["app_name"])
    desc = ""
    if dic_app.has_key("desc"):
        desc = dic_app["desc"]
    description = """%s&element=<subcategory>internet-utility</subcategory><category>general-internet</category><technology>browser-based</technology><description>%s</description>"""%(name,desc)
    elements_1 = """%s<risk>1</risk><evasive-behavior>yes</evasive-behavior><consume-big-bandwidth>no</consume-big-bandwidth><used-by-malware>no</used-by-malware>"""%(description)
    elements_2 = """%s<able-to-transfer-file>no</able-to-transfer-file><has-known-vulnerability>no</has-known-vulnerability><tunnel-other-application>yes</tunnel-other-application>"""%(elements_1)
    elements_3 = """%s<tunnel-applications>no</tunnel-applications><prone-to-misuse>no</prone-to-misuse><pervasive-use>no</pervasive-use><file-type-ident>no</file-type-ident>"""%(elements_2)
    parent_app = """%s<virus-ident>no</virus-ident><spyware-ident>no</spyware-ident><data-ident>no</data-ident><parent-app>%s</parent-app>"""%(elements_3,dic_app["parent-app"])
    rule_fim = urllib.urlopen(parent_app).read()
    regras_doc = xmltodict.parse(rule_fim)
    if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
        lista_saida.append(regras_doc)
    else: 
        sig = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/application/entry[@name='%s']/signature/entry[@name='%s']"""%(inserir,settings.FW_HOST,dic_app["app_name"],dic_app["app_name"])
        elements = """%s&element=<scope>protocol-data-unit</scope><order-free>no</order-free>"""%(sig)
        rule_fim = urllib.urlopen(elements).read()
        regras_doc = xmltodict.parse(rule_fim)
        if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
            lista_saida.append(regras_doc)
        else:
            and_cond = """%s&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/application/entry[@name='%s']/signature/entry[@name='%s']"""%(inserir,settings.FW_HOST,dic_app["app_name"],dic_app["app_name"])
            count = 1
            for palavra in dic_app["url"]:
                and_cond2 = """%s/and-condition/entry[@name='And Condition %s']/or-condition/entry[@name='Or Condition %s']/operator/pattern-match"""%(and_cond,count,count)
                pattern = """%s&element=<pattern>%s</pattern><context>http-req-host-header</context>"""%(and_cond2,palavra.replace(".","\."))
                count = count + 1
                rule_fim = urllib.urlopen(pattern).read()
                regras_doc = xmltodict.parse(rule_fim)
                if (regras_doc["response"]["@status"] == "error") or (regras_doc == None):
                    lista_saida.append(regras_doc)
                if count == 3:
                    break
    return lista_saida
