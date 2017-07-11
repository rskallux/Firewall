#!/bin/bash

### BEGIN INIT INFO
# Provides:          firewall.sh
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start firewall at boot time
# Description:       Enable service provided by firewall.sh.
### END INIT INFO

##---| Nao alterar daqui pra cima configuracoes de init do script

##---| Elaborado por Luiz Peterli  www.opentech.etc.br


##---| Declarar Variaveis placas de rede
IF_LINK="eth0"         #Rede de onde vem a internet
IF_INT="eth1" #Rede interna da estrutura
LAN_INT="192.168.0.0/24"



############################################
### Logando os acessos das redes sociais ###
############################################
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "facebook.com" -m limit --limit 6/m --limit-burst 1 -j LOG --log-prefix " acesso facebook: " --log-level alert
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "twitter.com"  -m limit --limit 6/m --limit-burst 1 -j LOG --log-prefix " acesso twitter: " --log-level alert
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "plus.google.com" -m limit --limit 6/m --limit-burst 1 -j LOG --log-prefix " acesso plus: " --log-level alert
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "instagram.com" -m limit --limit 6/m --limit-burst 1 -j LOG --log-prefix " acesso instagram: " --log-level alert
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "linkedin.com" -m limit --limit 6/m --limit-burst 1 -j LOG --log-prefix " acesso linkedin: " --log-level alert



######################################################################
### Bloqueando os acessos a redes sociais pela eth1 e na porta 443 ###
######################################################################

iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "facebook.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "twitter.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "plus.google.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "instagram.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -i $IF_INT -m string --algo bm --string "linkedin.com" -j DROP




#####################################################################################
### Bloqueando os acessos a redes sociais na porta 443 e com origem da rede local ###
#####################################################################################

iptables -A FORWARD -p tcp --dport 443 -s $LAN_INT -m string --algo bm --string "facebook.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -s $LAN_INT -m string --algo bm --string "twitter.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -s $LAN_INT -m string --algo bm --string "plus.google.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -s $LAN_INT -m string --algo bm --string "instagram.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -s $LAN_INT -m string --algo bm --string "linkedin.com" -j DROP





#####################################################################################
### Bloqueando os acessos a redes sociais na porta 443 e com destino a rede local ###
#####################################################################################

iptables -A FORWARD -p tcp --dport 443 -d $LAN_INT -m string --algo bm --string "facebook.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -d $LAN_INT -m string --algo bm --string "twitter.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -d $LAN_INT -m string --algo bm --string "plus.google.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -d $LAN_INT -m string --algo bm --string "instagram.com" -j DROP
iptables -A FORWARD -p tcp --dport 443 -d $LAN_INT -m string --algo bm --string "linkedin.com" -j DROP






###############################################################################################################
### Bloqueando os acessos a redes sociais nas portas 80 e 443 com origem na eth1 e com destino a rede local ###
###############################################################################################################

iptables -A FORWARD -p tcp -i $LAN_INT -m multiport --dport 80,443  -d $LAN_INT -m string --algo bm --string "facebook.com" -j DROP
iptables -A FORWARD -p tcp -i $LAN_INT -m multiport --dport 80,443  -d $LAN_INT -m string --algo bm --string "twitter.com" -j DROP
iptables -A FORWARD -p tcp -i $LAN_INT -m multiport --dport 80,443  -d $LAN_INT -m string --algo bm --string "plus.google.com" -j DROP
iptables -A FORWARD -p tcp -i $LAN_INT -m multiport --dport 80,443  -d $LAN_INT -m string --algo bm --string "instagram.com" -j DROP
iptables -A FORWARD -p tcp -i $LAN_INT -m multiport --dport 80,443  -d $LAN_INT -m string --algo bm --string "linkedin.com" -j DROP





###########################################################
### Liberando acesso as redes Sociais por números de IP ###
###########################################################

iptables -A FORWARD -i $IF_INT -s 192.168.0.2 -m string --algo bm --string "facebook.com" -j ACCEPT
iptables -I FORWARD -i $IF_INT -s 192.168.0.2 -m string --algo bm --string "twitter.com" -j ACCEPT
iptables -A FORWARD -i $IF_INT -s 192.168.0.2 -m string --algo bm --string "plus.google.com" -j ACCEPT
iptables -A FORWARD -i $IF_INT -s 192.168.0.2 -m string --algo bm --string "instagram.com" -j ACCEPT
iptables -A FORWARD -i $IF_INT -s 192.168.0.2 -m string --algo bm --string "linkedin.com" -j ACCEPT




####################################################################
### Liberando acesso as redes Sociais por números de Mac Address ###
####################################################################


iptables -A FORWARD -m mac --mac-source a1:b2:c3:e4:f5 -m string --algo bm --string "facebook.com" -j ACCEPT 
iptables -A FORWARD -m mac --mac-source a1:b2:c3:e4:f5 -m string --algo bm --string "twitter.com" -j ACCEPT
iptables -A FORWARD -m mac --mac-source a1:b2:c3:e4:f5 -m string --algo bm --string "plus.google.com" -j ACCEPT
iptables -A FORWARD -m mac --mac-source a1:b2:c3:e4:f5 -m string --algo bm --string "instagram.com" -j ACCEPT
iptables -A FORWARD -m mac --mac-source a1:b2:c3:e4:f5 -m string --algo bm --string "linkedin.com" -j ACCEPT


