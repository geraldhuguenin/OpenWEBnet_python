# -*- coding: utf-8 -*-
"""
Created on Sun Dec 19 10:08:43 2021
Programme de codage du mot de passe OPEN pour Myhome serveur
@author: Gérald Huguenin gerald.huguenin@gmail.com
"""
import hashlib
string='xxxxxxxxxx' #mot de passe OPEN
encoded=string.encode()
result = hashlib.sha256(encoded)
m=hashlib.sha256()
m.update(b"MonMotDePasse")
r=m.hexdigest()
print(r) #imprime la clé de codage à insérer dans le programme principal