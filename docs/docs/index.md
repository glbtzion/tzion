# Bem vindo ao tzion
#
####Estrutura do Tzion

O **tzion** é fruto do primero esforço de desenvolvimento de alguns dos Analistas do time Suporte Segurança da GLB. Ou seja, não somos desenvolvedores, somos apenas *scripteiros* que resolveram brincar de fazer uma api, usando **Flask** (http://www.fullstackpython.com/flask.html) e **MongoDB** (http://www.mongodb.org/) para permitir que um determinado grupo de usuários consiga consultar e alterar regras dentro de um Firewall (FW) Palo Alto, sem que seja necessário logar no equipamento para fazer uso de sua gui. Por esse motivo, obviamente, acreditamos que a *qualidade do código* certamente será questionada por qualquer pythonista de plantão. **Sugestões e melhorias podem ser enviadas através do https://github.com/glbtzion/tzion**

Na primeira implementação o tzion foi utilizado para __escreve/altera/apaga/lista__ regras de um Firewall Palo Alto que foi configurado para trabalhar como proxy transparente para os servidores de Back-end (internos) de uma organização que precisam acessar sites web na internet.

Nessa implementação, apenas o usuários que possuem conta no LDAP da empresa conseguem utilizar a api. Além de autenticado, o usuário da api precisa ter sido inserido em um dos grupos autorizados a realizar alterações no FW em questão. 

####Consultando regras existentes no FW através do tzion - **Método GET**
    curl -H "Content-type: application/json" -X GET http://tzion.mycompany.com/tzion -d '{"user":"####", "password":"####", "regra":{"source": ["Host_2.2.2.2", "Net_10.2.0.0_16"], "method":"exact","url": ["www.ufrj.br", "uerj.br"]}}'

####Os campos obrigatórios do Json são **user**, **password** e **regra**. 
    '{"user":"####", "password":"####", "regra":{ }}'

A api utiliza os dados contidos nas chaves user e password para autenticar seus usuários e verificar suas permissões, na API de autenticação da organização.
No código a API de autenticação é chamada de https://auth-server.mycompany.com

Na chave **regra** devem ser inseridos os parametros funcionais da API.

####Consultas em função do __nome da regra__
    curl -H "Content-type: application/json" -X GET http://tzion.mycompany.com/tzion -d '{"user":"####", "password":"####","regra":{"name":"Regra Teste","method":"exact"}}'

Em consultas (GET) a chave **method** é obrigatória.

####Consultas em função do __endereço de origem__
    curl -H "Content-type: application/json" -X GET http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"source": ["Net_10.28.0.0_22","Host_10.11.31.10"], "method":"any"}}'

Nesse caso a chave method deve ser setada para **any**. Assim, a api vai retornar todas as regras que possuem pelo menos um dos endereços de origem informados.

####Consultas em função do __endereço de destino__
    curl -H "Content-type: application/json" -X GET http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"destination": ["Host_200.141.95.15","Host_200.141.95.16"], "method":"any"}}'

####Consultas em função do __serviço, por exemplo TCP_443, TCP_80 ou any__
    curl -H "Content-type: application/json" -X GET http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"service":["any"], "method":"any"}}'


####Inserindo regras no Firewall - **Método POST**
    curl -H "Content-type: application/json" -X POST http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"name": "Regra Teste","source": ["Host_2.2.2.2","Net_10.2.0.0_16"], "url": ["www.globo.com", "uerj.br"], "parent-app": "web-browsing", "app_name": "app_teste"}}'

Se a API for utilizada enquanto alguém está editando o FW, as alterações serão gravadas mas não comitadas imediatamente. **Quando o analista concluir suas alterações o commit aplicará as alterações no FW.**

####Inserindo regras no Firewall **sem definir a URL do site a ser acessado**
    curl -H "Content-type: application/json" -X POST http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"name": "Regra Teste","source": ["Host_2.2.2.3"], "destination": ["Host_11.10.9.8"], "service":["any"]}}'


    curl -H "Content-type: application/json" -X POST http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"name": "Regra Teste","source": ["Host_2.2.2.3"], "destination": ["Host_11.10.9.8"], "service":["TCP_80"]}}'


    curl -H "Content-type: application/json" -X POST http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"name": "Regra Teste","source": ["Host_2.2.2.3"], "destination": ["Host_11.10.9.8"], "service":["TCP_1935"]}}'


Caso o tzion encontre uma policie semelhante a regra pretendida, os sources que não estão contidos na policie existente serão inseridos nela. Ou seja, a policie existente será atualizada, para evitar a criação de uma nova regra com os mesmos valores.

####Criando regras no FW **em função do endereço do site que se deseja acessar**

Caso a chave **url** seja enviada junto com a chave **destination**, o tzion ignorará a chave “destination”, pois trata-se da criação de uma regra em que o destino é uma URL (Layer 7). Quando isso acontece, as chaves **parent-app** e **app_name** são obrigatórias.

    curl -H "Content-type: application/json" -X POST http://tzion.mycompany.com/tzion -d '{"user":"####","password":"####","regra":{"name": "Regra Teste","source": ["Net_10.2.0.0_16"], "url": ["www.ufrj.br", "uerj.br"], "parent-app": "web-browsing", "app_name": "university"}}'

Caso as outras chaves não sejam fornecidas (excluindo-se a chave **source** desta situação), o tzion considerará o valor **any** para todos os casos, exceto quando a chave **url** estiver no contexto (**app** e **service** receberão os valores **app_teste** e **application-default**, respectivamente).

