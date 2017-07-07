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


##---| Declarar Variaveis placas de rede
WLAN=eth0         #Rede de onde vem a internet
LAN=eth1             #Rede interna da estrutura


##---| Declarar Variaveis ranges de redes
INTERNET="199.19.9.0/24"         #Rede de onde vem a internet
LOCAL="177.17.7.0/24"                #Rede interna da estrutura


##---| Declarar Variaveis IPs
GW="199.19.9.1"         #IP do Roteador de onde vem a internet
FW="177.17.7.1"          #IP da minha máquina Firewall


##---| Informando a porta de acesso ssh
PSSH=22


##---| Carregamento de modulos
modprobe ip_tables
modprobe ipt_LOG
modprobe iptable_mangle
modprobe ipt_tos


##---| Caminhos do IPTABLES
PATH=/sbin:/bin:/usr/sbin:/usr/bin
IPT="/sbin/iptables"


##---| Limpeza de regras antigas
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t nat -Z
$IPT -t filter -F
$IPT -t filter -X
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t filter -Z


##---| Politicas de acesso padroes
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT  #Esse exemplo atende a um modelo de firewall permissivo, caso o seu firewall seja proibitivo o output deve ser sempre DROP fazendo a liberação de saída de regra por regra
$IPT -A INPUT -i lo -j ACCEPT


### ##################################### ###
### Regras de Firewall contra ataques ao servidor   ###
### ##################################### ###


##---| Bloqueio contra Scaners ocultos
$IPT -A FORWARD -p tcp --tcp-flags SYN,ACK, FIN, -m limit --limit 1/s -j ACCEPT


##---| Bloqueio contra Responses bogus
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses


##---| Bloqueio contra identificacao por traceroute
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route


##---| Bloqueio contra spoofing
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter


##---| Bloqueio contra o ping da morte
echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all
$IPT -N PING-MORTE
$IPT -A INPUT -p icmp --icmp-type echo-request -j PING-MORTE
$IPT -A PING-MORTE -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A PING-MORTE -j DROP


##---| Bloqueio contra o ataque do tipo Syn-flood
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
$IPT -N syn-flood
$IPT -A INPUT -i $WLAN -p tcp --syn -j syn-flood
$IPT -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A syn-flood -j DROP


##---| Bloqueio contra ataque de força bruta no SSH
$IPT -N SSH-BRUT-FORCE
$IPT -A INPUT -i $WLAN -p tcp --dport $PSSH -j SSH-BRUT-FORCE
$IPT -A SSH-BRUT-FORCE -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A SSH-BRUT-FORCE -j DROP


#---------| Liberando e logando o SSH na porta 22 (Esse campo loga todos os acessos do SSH na porta 22 no arquivo de log no local /var/log/krn.log
$IPT -A INPUT -p tcp -d $GW --dport $PSSH -m limit --limit 5/minute --limit-burst 1 -j LOG --log-prefix "ssh22 " --log-level alert
$IPT -A INPUT -p tcp -d $GW --dport $PSSH -j ACCEPT


#---| Bloqueio Broadcast
$IPT -I INPUT -p udp -m state --state NEW -m udp --dport 137 -j DROP
$IPT -I INPUT -p tcp -m state --state NEW -m tcp --dport 137 -j DROP
$IPT -A FORWARD -p udp --dport 135:139 -j DROP
$IPT -A FORWARD -p udp --sport 135:139 -j DROP