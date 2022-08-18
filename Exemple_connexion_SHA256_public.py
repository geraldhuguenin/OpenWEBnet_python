# -*- coding: utf-8 -*-
"""
Created on Fri Dec 17 15:21:19 2021

@author: Gérald Huguenin gerald.huguenin@gmail.com

Exemple de programme pour se connecter au MyHomeserver1 (Legrand) 
Utilise le protocole de cryptage SAM


"""
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import hashlib



def decodage_128_char(str) :  #décodage de la chaine format 128 char
    R=''
    for i in range(int((len(str))/2)):
        char = int(str[(2*i):(2*i+2):])
        if char ==0:
            R = R + '0'
        if char ==1:
            R = R + '1'
        if char ==2:
            R = R + '2'
        if char ==3:
            R = R + '3'
        if char ==4:
            R = R + '4'
        if char ==5:
            R = R + '5'
        if char ==6:
            R = R + '6'
        if char ==7:
            R = R + '7'
        if char ==8:
            R = R + '8'
        if char ==9:
            R = R + '9'
        if char ==10:
            R = R + 'a'
        if char ==11:
            R = R + 'b'
        if char ==12:
            R = R + 'c'
        if char ==13:
            R = R + 'd'
        if char ==14:
            R = R + 'e'
        if char ==15:
            R = R + 'f'
    return R

def encodage_hex_64_char(str) :  #encodage en chaine 128 char (str doit être byte array)
    R=''
    for i in range(len(str)):
        char = str[i]
        if char =='0':
            R = R + '00'
        if char =='1':
            R = R + '01'
        if char =='2':
            R = R + '02'
        if char =='3':
            R = R + '03'
        if char =='4':
            R = R + '04'
        if char =='5':
            R = R + '05'
        if char =='6':
            R = R + '06'
        if char =='7':
            R = R + '07'
        if char =='8':
            R = R + '08'
        if char =='9':
            R = R + '09'
        if char == 'a':
            R = R + '10'
        if char =='b':
            R = R + '11'
        if char =='c':
            R = R + '12'
        if char =='d':
            R = R + '13'
        if char =='e':
            R = R + '14'
        if char =='f':
            R = R + '15'
    return R

#Paramètres de connexion à la passerelle BUS/SCS
buffer_size =2048
ip_F455='192.168.1.117'
port_F455=20000

Ra = b''  # clé reçue
Rb = '01150306100314120401040506080906000812050206130513051307001109000700010815090013010908010408110501030607010414130803010400061405'  #clé envoyée
# La clé Rb envoyée par le programme est toujours la même... on peut améliorer en générant une clé aléatoire
A = '736F70653E'  # Identité client (ATTENTION aux majuscules pour l'hexa)
B = '636F70653E'   # Identité serveur
Kab = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
#clé de codage du mot de passe OPEN (voir programme spécifique pour le cryptage de cette clé)


#ouverture du socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip_F455,port_F455))


data=s.recv(buffer_size) #attente d'un message du server (doit envoyer *#*1## = ACK)
print ("1 : ",data)  #impression pour surveiller l'échange de données (peut être supprimé)
messg='*99*9##'
s.send(messg.encode()) #envoi de la requête "commande"
data=s.recv(buffer_size)
print ("2 : ",data) #surveillance (on doit recevoir *98*2## qui correspond à la demande d'une connexion sécurisée SHA256)
s.send(b'*#*1##')
Ra=s.recv(buffer_size) #envoi de ACK pour accepter le protocol de connexion sécurisé avec SHA256
print ("Ra = ",Ra)  #data contient la clé en hexa entre *#....##
Ra = Ra[2:-2] # On récupère la clé sans les entêtes

Ra = decodage_128_char(Ra) #conversion en chaine de caractère (format hexa)
Rb = decodage_128_char(Rb)


msg = Ra+Rb+A+B+Kab #construction du message codé SHA256


m=hashlib.sha256()
m.update(bytes(msg,'latin-1'))
r=m.hexdigest() #codage (format hexa)
Rb = encodage_hex_64_char(Rb) 
r=encodage_hex_64_char(r) #encodage en format "hexa sur 2 digits" avec 1 =>01 et F => 15
r='*#'+Rb+'*'+r+'##' #construction de la réponse cryptée

s.send(r.encode())

data=s.recv(buffer_size)
print ("4 : ",data) #on doit recevoir codé SHA256 Ra+Rb+Kab


s.send(b'*#*1##') #envoi de ACK pour valider


s.send(b'*1*1*06##') #envoi d'une commande d'allumage d'une lampe
data=s.recv(buffer_size)

s.close()