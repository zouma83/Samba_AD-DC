# Samba_AD-DC
Samba Active Directory - Domain Controller

```
|-------------------------------------------------------------------------------------------------|
|     ...                         Tuto Install - AD DC Samba                             ...      |
|    (o-o)                       FM - GP3 - TSSI 27 - AFPA 83                           (o-o)     |
|ooO--(_)--Ooo                    Installation sur VMware 14                        ooO--(_)--Ooo |
|-------------------------------------------------------------------------------------------------|


   /----------------------------\
   |                            |
   |   Installation sur :       |
   |                            |
   |   * Debian 7.x Serveur *   |
   |     ------------------   	|
   |                            |
   |            de :            |
   |                            |
   | * Samba Active Directory * |
   |   ----------------------   | 
   |                            |
   \----------------------------/ 



                                   _,met$$$$$gg.
                               ,g$$$$$$$$$$$$$$$P.
                             ,g$$P""       """Y$$.".
                            ,$$P'              `$$$. 
                          ',$$P       ,ggs.     `$$b:
                          `d$$'     ,$P"'   .    $$$
                           $$P      d$'     ,    $$P
                           $$:      $$.   -    ,d$$'
                           $$;      Y$b._   _,d$P'
                           Y$$.    `.`"Y$$$$P"' 
                           `$$b      "-.__
                            `Y$$b
                             `Y$$.
                               `$$b.
                                 `Y$$b.
                                   `"Y$b._
                                       `""""

                       _,           _,      ,'`.
                     `$$'         `$$'     `.  ,'
                      $$           $$        `'
                      $$           $$         _,           _ 
                ,d$$$g$$  ,d$$$b.  $$,d$$$b.`$$' g$$$$$b.`$$,d$$b.
               ,$P'  `$$ ,$P' `Y$. $$$'  `$$ $$  "'   `$$ $$$' `$$
               $$'    $$ $$'   `$$ $$'    $$ $$  ,ggggg$$ $$'   $$
               $$     $$ $$ggggg$$ $$     $$ $$ ,$P"   $$ $$    $$
               $$    ,$$ $$.       $$    ,$P $$ $$'   ,$$ $$    $$
               `$g. ,$$$ `$$._ _., $$ _,g$P' $$ `$b. ,$$$ $$    $$
                `Y$$P'$$. `Y$$$$P',$$$$P"'  ,$$. `Y$$P'$$.$$.  ,$$.




                   #                                                                               
   ############### ##  ###############    ###################    ###############    ###############
   ###             #  ###          ###    ###     ###      ###   ###          ###   ###         ###
   ##                 ###          ###    ###     ###      ###   ###          ###   ###          ##
   ###############    ################    ###     ###      ###   ###############    ###############
               ###    ###          ###    ###     ###      ###   ###          ###   ###          ##
 #             ###    ###          ###    ###     ###      ###   ###          ###   ###          ##
## ###############    ###          ###    ###     ###      ###   ###############    ###          ##
 #
```
--------------------

## Pré-requis:
> Serveur => Debian 7.x
> 
> Services => DynDNS (Bind9) - DHCP - NTP
> 
> (cf. web & tutos webadonf)

--------------------

## O - Confs de départ:
> /etc/network/interfaces :=>
```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
auto eth0
iface eth0 inet static
        address 172.16.13.30
        netmask 255.255.0.0
        network 172.16.0.0
        broadcast 172.16.255.255
        gateway 172.16.0.252
        post-up iptables-restore < /etc/iptables.save
        # dns-* options are implemented by the resolvconf package, if installed
        dns-nameservers 172.16.0.252

allow-hotplug eth1
auto eth1
iface eth1 inet static
        address 192.168.13.254
        netmask 255.255.255.0
        network 192.168.13.0
        dns-nameservers 192.168.13.254 172.16.0.252
        dns-search opti09.lan
```

> /etc/hosts :=>
```
127.0.0.1       localhost.localdomain   localhost
192.168.13.254  srvdeb7.opti09.lan      srvdeb7

# The following lines are desirable for IPv6 capable hosts
#::1     localhost ip6-localhost ip6-loopback
#ff02::1 ip6-allnodes
#ff02::2 ip6-allrouters
```

>/etc/hostname :=>
```
srvdeb7.opti09.lan
```

> /etc/resolv.conf :=>
```
domain opti09.lan
search opti09.lan
nameserver 127.0.0.1
nameserver 192.168.13.254
```

###### /!\ Si le dynDNS a été configuré selon le tuto suivant : /!\
###### "3 - Gestion dynamique du DNS avec Bind9 sous Debian Squeeze _ Le webadonf.net déblogue!.pdf"
###### => Il convient de commenter la ligne paramétrant le nom attribué aux entrées DNS
 
>/etc/dhcp/dhcpd.conf :=>
```
#ddns-hostname = concat ("dhcp-opti09","-",binary-to-ascii(10,8,"-",leased-address));
```

--------------------

## I - Installation :
```
# apt-get update && apt-get dist-upgrade
# apt-get install build-essential libacl1-dev libattr1-dev libblkid-dev libgnutls-dev libreadline-dev python-dev python-dnspython gdb pkg-config libpopt-dev libldap2-dev dnsutils libbsd-dev attr acl krb5-user docbook-xsl libcups2-dev libpam0g-dev
```
###### => Indiquer le nom du Royaume (=domaine) (en capitales) (OPTI09.LAN)
###### => Indiquer le nom du serveur (en minuscule) (srvdeb7)
###### => Indiquer le nom du serveur (en minuscule) (srvdeb7)

###### => Récupération de Samba :=>
```
# wget http://ftp.samba.org/pub/samba/samba-latest.tar.gz
# tar -zxvf samba-latest.tar.gz
# cd samba-4.7.5/
# ./configure --enable-debug --enable-selftest
```
###### (/!\ possiblement un peu long /!\)
```
# make && make install
```
###### (/!\ possiblement tres long /!\)


--------------------

##  II - Configurations & Adaptations :

###### => déclaration du domaine dans Samba, de l'ad, du rôle dc, du dns et de l'interface à utiliser:
```
# /usr/local/samba/bin/samba-tool domain provision --option="interfaces=lo eth1" --option="bind interfaces only=yes" --use-rfc2307 --interactive
```
###### => Questionnaire configuration Samba :=>
> Realm [OPTI09.LAN]: valider si ok
>
> Domain [OPTI09]: valider si ok
>
> Server Role [dc]: valider si ok
>
> DNS backend [SAMBA_INTERNAL]: BIND9_DLZ
>
> Renseigner le mot de passe d'administration de l'AD & confirmer (le login sera Administrator)

###### => sur le compte rendu de la configuration: vérifier que c'est la bonne interface réseau (@IP) qui a été selectionnée.

###### => modification des fichiers de base de Bind:
```
# nano /etc/bind/named.conf
```
```
include "/etc/bind/named.conf.options";
#include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
include "/usr/local/samba/private/named.conf";
```

###### => correspondance Bind/Samba
```
# named -v
```
```
BIND 9.8.4
```
```
# nano /usr/local/samba/private/named.conf
```
###### (Verifier que c'est la ligne correspondant à la bonne version de Bind9 qui est decommentée)

###### => gestion des dossiers, des liens et des autorisations de Bind
###### /!\ normalement déja effectué la configuration de Samba, donc inutile: /!\
```
# mkdir /usr/local/samba/private/dns/
# ln -s /usr/local/samba/private/sam.ldb /usr/local/samba/private/dns/sam.ldb
```
###### => à faire en root:
```
# ln -s /usr/local/samba/private/sam.ldb.d /usr/local/samba/private/dns/sam.ldb.d
# chmod 755  /usr/local/samba/private
# chmod 750  /usr/local/samba/private/sam.ldb.d
# chgrp bind /usr/local/samba/private/sam.ldb.d /usr/local/samba/private/sam.ldb
# chmod 660  /usr/local/samba/private/sam.ldb
# chgrp bind /usr/local/samba/private/sam.ldb.d/*
# chmod 660  /usr/local/samba/private/sam.ldb.d/*
# chown bind /usr/local/samba/private/dns.keytab
```

###### => ajout d'options à Bind:
```
# nano  /etc/bind/named.conf.options
```
```
options {
...
tkey-gssapi-keytab "/usr/local/samba/private/dns.keytab";
...
allow-query {  any;};
...
};
```

###### indication à Bind de ne s'interesser qu'à l'ipv4:
```
# nano /etc/default/bind9
```
```
OPTIONS="-4 -u bind"
```

###### => vérification que Samba est bien relié à la bonne interface réseau
```
# nano /usr/local/samba/etc/smb.conf
```

###### => & correction de l'interface si besoin:
###### => forcer l'utilisation du DNS et corriger si mauvaise interface:
```
[global]
...
bind interfaces only = yes
interfaces = lo eth1
```

###### => indication du dns forwarder
```
[global]
...
dns forwarder = 172.16.0.252
```

###### => configuration de Kerberos:
```
# nano /usr/local/samba/share/setup/krb5.conf
```
```
[libdefaults]
	default_realm = OPTI09.LAN
	dns_lookup_realm = false
	dns_lookup_kdc = true

[realms]
	OPTI09.LAN = {
		kdc = SRVDEB7.OPTI09.LAN
		admin_server = SRVDEB7.OPTI09.LAN
	}

[domain_realm]
	.opti09.lan = OPTI09.LAN
	opti09.lan = OPTI09.LAN
```

###### => création d'un lien symbolique pour le fichier conf de Kerberos:
```
# ln -sf /usr/local/samba/share/setup/krb5.conf /etc/krb5.conf
```

###### => intégration du nom de domaine dans le DHCP:
```
# nano /etc/dhcp/dhcpd.conf
```
```
option domain-name "opti09.lan";
```

###### => désactiver la politique d'expiration du mot de passe de l'administrateur de l'AD (ou pas)
###### (/!\ semble poser des soucis avec Kerberos - l'utiliser plutot apres validation de l'install /!\)
```
# /usr/local/samba/bin/samba-tool user setexpiry administrator --noexpiry
```
###### => reboot


--------------------

##  III - Démarrage de Samba & tests & créations des premiers utilisateurs :

###### => vérification du bon fonctionnenemnt des services:
###### => NTP:
```
# ntpq -pn
# ntptrace
```
###### (/!\ stratum 3 /!\)
###### => BIND:
```
# named-checkconf /etc/bind/named.conf
# named-checkconf /etc/bind/named.conf.options
```
------------------------------------------------------------------------
###### => démarrage de Samba:
```
# /usr/local/samba/sbin/samba
```
------------------------------------------------------------------------

###### => vérification que Samba est bien démarré :
```
# ps axf | egrep "samba|smbd|nmbd|winbindd"
```
```
  2834 pts/0    S+     0:00                      \_ egrep samba|smbd|nmbd|winbindd
  2777 ?        Ss     0:00 /usr/local/samba/sbin/samba
  2778 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2781 ?        S      0:00  |   \_ /usr/local/samba/sbin/samba
  2789 ?        Ss     0:00  |       \_ /usr/local/samba/sbin/smbd -D --option=server role check:inhibit=yes --foreground
  2796 ?        S      0:00  |           \_ /usr/local/samba/sbin/smbd -D --option=server role check:inhibit=yes --foreground
  2797 ?        S      0:00  |           \_ /usr/local/samba/sbin/smbd -D --option=server role check:inhibit=yes --foreground
  2798 ?        S      0:00  |           \_ /usr/local/samba/sbin/smbd -D --option=server role check:inhibit=yes --foreground
  2779 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2780 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2782 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2783 ?        S      0:01  \_ /usr/local/samba/sbin/samba
  2784 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2785 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2786 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2787 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2791 ?        S      0:00  |   \_ /usr/local/samba/sbin/samba
  2792 ?        Ss     0:00  |       \_ /usr/local/samba/sbin/winbindd -D --option=server role check:inhibit=yes --foreground
  2794 ?        S      0:00  |           \_ /usr/local/samba/sbin/winbindd -D --option=server role check:inhibit=yes --foreground
  2811 ?        S      0:00  |           \_ /usr/local/samba/sbin/winbindd -D --option=server role check:inhibit=yes --foreground
  2816 ?        S      0:00  |           \_ /usr/local/samba/sbin/winbindd -D --option=server role check:inhibit=yes --foreground
  2788 ?        S      0:00  \_ /usr/local/samba/sbin/samba
  2790 ?        S      0:00  \_ /usr/local/samba/sbin/samba
```

###### => vérification des versions de Samba & SmbClient correspondent:
```
# /usr/local/samba/sbin/samba -V
# /usr/local/samba/bin/smbclient -V
```

###### => Tester les partages administratifs de SysVol, Netlogon, etc...
```
# /usr/local/samba/bin/smbclient -L localhost -U%
```
```
        Sharename       Type      Comment
        ---------       ----      -------
        netlogon        Disk
        sysvol          Disk
        IPC$            IPC       IPC Service (Samba 4.7.5)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
```

###### => Tester l'authentification Kerberos:
```
# /usr/local/samba/bin/smbclient //localhost/netlogon -UAdministrator -c
```
###### + Pass admin AD
```
smb: \> ls
  .                                   D        0  Thu Mar  8 12:27:00 2018
  ..                                  D        0  Thu Mar  8 12:27:04 201
smb: \> exit
```

###### => Tester les enregistrements du serveur dans le DNS :
```
# host srvdeb7.opti09.lan
```
```
srvdeb7.opti09.lan has address 192.168.13.254
```
```
# host -t SRV _ldap._tcp.opti09.lan
```
```
_ldap._tcp.opti09.lan has SRV record 0 100 389 srvdeb7.opti09.lan
```
```
# host -t SRV _kerberos._udp.opti09.lan
```
```
_kerberos._udp.opti09.lan has SRV record 0 100 389 srvdeb7.opti09.lan
```

###### => Création des premiers Utilisateurs:
```
# /usr/local/samba/bin/samba-tool user create toto
```
######  + indiquer & confirmer le mot de passe (/!\ politique restriction mot de passe /!\)

###### => suppression des fichiers d'install:
```
# rm -r samba-4.7.6/
# rm samba-latest.tar.gz
```

###### => reboot
###### /!\ + démarrage de Samba /!\


--------------------

##  IV - Connexion du premier client Windows au SambAD :

###### => rejoindre le domaine :=> opti09 + login/pass admin AD Kerberos
###### => connexion session	:=> opti09\toto + pass toto
###### /!\ ne pas valider trop vite la maj des vm-tools -> delogage precoce /!\

###### => ;)


--------------------

##  V - Ajout des outils RSAT (sur Win 7) :

###### => Installation outils RSAT:
> - récupérer les outils RSAT pour Win7 :=> http://www.microsoft.com/fr-fr/download/details.aspx?id=7887
> - les installer sur un pc en Win7
> - ajout des fonctionnalités Windows suivantes:
>  - Outils d'administration de serveur distant > Outils d'administration de fonctionnalités > Outils de gestion des stratégies de groupe
>  - Outils d'administration de serveur distant > Outils d'administration de rôles > Outils du serveur DNS
>  - Outils d'administration de serveur distant > Outils d'administration de rôles > Outils AD DS et AD LDS > tout cocher
>  - Outils d'administration de serveur distant > Outils d'administration de rôles > Outils AD DS et AD LDS > Outils AD DS > tout cocher
>  - accés aux outils d'administration:
>    Panneau de configuration > Système et sécurité > Outils d'administration


--------------------

##  VI - MAJ du DNS par le DHCP :

###### => création de la zone inversé dans le DNS depuis les RSATs du Win7
>	- outils d'administration > DNS > (exécuter en admin)
>	- connexion au serveur hébergeant le DNS
>	- "Zone de recherche inversée" > "nouvelle zone..."
>	- "Zone principale" > "vers tous les serveurs..." (choix 2)
>	- "Zone de recherche inversée IPv4"
>	- "ID réseau" > 192.168.13
>	- "N'autoriser que les mises à jour dynamiques sécurisées..."
>	- Valider

###### => éteindre tout les clients raccordés à l'AD

######  => création et conf d'un utilisateur dhcp dans l'AD
```
# /usr/local/samba/bin/samba-tool user create dhcpduser --description="Unprivileged user for TSIG-GSSAPI DNS updates via ISC DHCP server" --random-password
# /usr/local/samba/bin/samba-tool user setexpiry dhcpduser --noexpiry
# /usr/local/samba/bin/samba-tool group addmembers DnsAdmins dhcpduser
```

###### => export du keytab
```
# /usr/local/samba/bin/samba-tool domain exportkeytab --principal=dhcpduser@OPTI09.LAN /etc/dhcpduser.keytab
# chown root:root  /etc/dhcpduser.keytab
# chmod 400  /etc/dhcpduser.keytab
```

###### => Création du script pour les MAJ du DNS par le DHCP:
```
# nano /usr/local/bin/dhcp-dyndns.sh
```
###### => copier/coller :
```
#!/bin/bash

# /usr/local/bin/dhcp-dyndns.sh

# This script is for secure DDNS updates on Samba 4
# Version: 0.8.9

# Uncomment the next line if using a self compiled Samba and adjust for your PREFIX
#PATH="/usr/local/samba/bin:/usr/local/samba/sbin:$PATH"
BINDIR=$(samba -b | grep 'BINDIR' | grep -v 'SBINDIR' | awk '{print $NF}')
WBINFO="$BINDIR/wbinfo"

# DNS domain
domain=$(hostname -d)
if [ -z ${domain} ]; then
    logger "Cannot obtain domain name, is DNS set up correctly?"
    logger "Cannot continue... Exiting."
    exit 1
fi

# Samba 4 realm
REALM=$(echo ${domain^^})

# Additional nsupdate flags (-g already applied), e.g. "-d" for debug
NSUPDFLAGS="-d"

# krbcc ticket cache
export KRB5CCNAME="/tmp/dhcp-dyndns.cc"

# Kerberos principal
SETPRINCIPAL="dhcpduser@${REALM}"
# Kerberos keytab
# /etc/dhcpduser.keytab
# krbcc ticket cache
# /tmp/dhcp-dyndns.cc
TESTUSER="$($WBINFO -u) | grep 'dhcpduser')"
if [ -z "${TESTUSER}" ]; then
    logger "No AD dhcp user exists, need to create it first.. exiting."
    logger "you can do this by typing the following commands"
    logger "kinit Administrator@${REALM}"
    logger "samba-tool user create dhcpduser --random-password --description=\"Unprivileged user for DNS updates via ISC DHCP server\""
    logger "samba-tool user setexpiry dhcpduser --noexpiry"
    logger "samba-tool group addmembers DnsAdmins dhcpduser"
    exit 1
fi

# Check for Kerberos keytab
if [ ! -f /etc/dhcpduser.keytab ]; then
    echo "Required keytab /etc/dhcpduser.keytab not found, it needs to be created."
    echo "Use the following commands as root"
    echo "samba-tool domain exportkeytab --principal=${SETPRINCIPAL} /etc/dhcpduser.keytab"
    echo "chown XXXX:XXXX /etc/dhcpduser.keytab"
    echo "Replace 'XXXX:XXXX' with the user & group that dhcpd runs as on your distro"
    echo "chmod 400 /etc/dhcpduser.keytab"
    exit 1
fi

# Variables supplied by dhcpd.conf
action=$1
ip=$2
DHCID=$3
name=${4%%.*}

usage()
{
echo "USAGE:"
echo "  $(basename $0) add ip-address dhcid|mac-address hostname"
echo "  $(basename $0) delete ip-address dhcid|mac-address"
}

_KERBEROS () {
# get current time as a number
test=$(date +%d'-'%m'-'%y' '%H':'%M':'%S)
# Note: there have been problems with this
# check that 'date' returns something like
# 04-09-15 09:38:14

# Check for valid kerberos ticket
#logger "${test} [dyndns] : Running check for valid kerberos ticket"
klist -c /tmp/dhcp-dyndns.cc -s
if [ "$?" != "0" ]; then
    logger "${test} [dyndns] : Getting new ticket, old one has expired"
    kinit -F -k -t /etc/dhcpduser.keytab -c /tmp/dhcp-dyndns.cc "${SETPRINCIPAL}"
    if [ "$?" != "0" ]; then
        logger "${test} [dyndns] : dhcpd kinit for dynamic DNS failed"
        exit 1;
    fi
fi

}

# Exit if no ip address or mac-address
if [ -z "${ip}" ] || [ -z "${DHCID}" ]; then
    usage
    exit 1
fi

# Exit if no computer name supplied, unless the action is 'delete'
if [ "${name}" = "" ]; then
    if [ "${action}" = "delete" ]; then
        name=$(host -t PTR "${ip}" | awk '{print $NF}' | awk -F '.' '{print $1}')
    else
        usage
        exit 1;
    fi
fi

# Set PTR address
ptr=$(echo ${ip} | awk -F '.' '{print $4"."$3"."$2"."$1".in-addr.arpa"}')

## nsupdate ##
case "${action}" in
add)
    _KERBEROS

nsupdate -g ${NSUPDFLAGS} << UPDATE
server 127.0.0.1
realm ${REALM}
update delete ${name}.${domain} 3600 A
update add ${name}.${domain} 3600 A ${ip}
send
UPDATE
result1=$?

nsupdate -g ${NSUPDFLAGS} << UPDATE
server 127.0.0.1
realm ${REALM}
update delete ${ptr} 3600 PTR
update add ${ptr} 3600 PTR ${name}.${domain}
send
UPDATE
result2=$?
;;
delete)
     _KERBEROS

nsupdate -g ${NSUPDFLAGS} << UPDATE
server 127.0.0.1
realm ${REALM}
update delete ${name}.${domain} 3600 A
send
UPDATE
result1=$?

nsupdate -g ${NSUPDFLAGS} << UPDATE
server 127.0.0.1
realm ${REALM}
update delete ${ptr} 3600 PTR
send
UPDATE
result2=$?
;;
*)
echo "Invalid action specified"
exit 103
;;
esac

result="${result1}${result2}"

if [ "${result}" != "00" ]; then
    logger "DHCP-DNS Update failed: ${result}"
else
    logger "DHCP-DNS Update succeeded"
fi

exit ${result}

```

###### => modification des permissions du script:
```
# chmod 755 /usr/local/bin/dhcp-dyndns.sh
```

###### => modification de la conf du DHCP:
###### => copie du fichier dhcpd.conf de départ:
```
# cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.orig
```
###### => edition de dhcpd.conf:
```
# nano /etc/dhcp/dhcpd.conf
```
```
#
# Sample configuration file for ISC dhcpd for Debian
#
#

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;
#ddns-ttl 3600;

# option definitions common to all supported networks...
#option domain-name "opti09.lan";
#option domain-name-servers srvdeb7.opti09.lan;

#default-lease-time 600;
#max-lease-time 7200;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#log-facility local7;

# No service will be given on this subnet, but declaring it helps the
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
subnet 192.168.13.0 netmask 255.255.255.0 {
        option subnet-mask 255.255.255.0;
        option broadcast-address 192.168.13.255;
        option time-offset 0;
        option routers 192.168.13.254;
        option domain-name "opti09.lan";
        option domain-name-servers 192.168.13.254, 172.16.0.252;
        option netbios-name-servers 192.168.13.254, 172.16.0.252;
        option ntp-servers 192.168.13.254;
        pool {
                max-lease-time 1800; # 30 minutes
                range 192.168.13.1 192.168.13.200;
                }
        }

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.fugue.com";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.fugue.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of "foo";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of "foo";
#    range 10.0.29.10 10.0.29.230;
#  }
#}

#key dynamic-update-dns-key {
#       algorithm HMAC-MD5;
#       secret "HmOHQ6RFJiPDmuc8k5PEYzSD3ANpr5zb9leDHD7tIhcCcFJ9j2MAnVzYL11fckn71lwUAYrZOt2ZeR9cIOehHw==";
#       };

#zone 13.168.192.in-addr.arpa. {
#       key dynamic-update-dns-key;
#       primary 192.168.13.254;
#       }

#zone opti09.lan. {
#       key dynamic-update-dns-key;
#       primary 192.168.13.254;
#       }

#ddns-hostname = concat ("dhcp-flocal","-",binary-to-ascii(10,8,"-",leased-address));

on commit {
set noname = concat("dhcp-", binary-to-ascii(10, 8, "-", leased-address));
set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
set ClientDHCID = binary-to-ascii(16, 8, ":", hardware);
set ClientName = pick-first-value(option host-name, config-option-host-name, client-name, noname);
log(concat("Commit: IP: ", ClientIP, " DHCID: ", ClientDHCID, " Name: ", ClientName));
execute("/usr/local/bin/dhcp-dyndns.sh", "add", ClientIP, ClientDHCID, ClientName);
}

on release {
set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
set ClientDHCID = binary-to-ascii(16, 8, ":", hardware);
log(concat("Release: IP: ", ClientIP));
execute("/usr/local/bin/dhcp-dyndns.sh", "delete", ClientIP, ClientDHCID);
}

on expiry {
set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
# cannot get a ClientMac here, apparently this only works when actually receiving a packet
log(concat("Expired: IP: ", ClientIP));
# cannot get a ClientName here, for some reason that always fails
execute("/usr/local/bin/dhcp-dyndns.sh", "delete", ClientIP, "", "0");
}
```

###### => redémarrer le service DHCP:
```
# /etc/init.d/isc-dhcp-server restart
```

###### => reboot



--------------------

##  VII - Connexion des Clients Linux au SambAD :

###### sur le client linux :
```
# apt-get update && apt-get dist-upgrade
```
######1- définir le nom de la machine et la conf du reseau:
```
# nano /etc/hostname
```
```
DEBIAN-8-01.opti09.lan
```
```
# nano /etc/hosts
```
```
127.0.0.1       localhost
127.0.1.1       DEBIAN-8-01.opti09.lan  DEBIAN-8-01

# The following lines are desirable for IPv6 capable hosts
#::1     localhost ip6-localhost ip6-loopback
#ff02::1 ip6-allnodes
#ff02::2 ip6-allrouters
```
###### => reboot
###### => check:
```
# hostname
=
# hostname -f
```

```
# nano /etc/resolv.conf
```
```
search opti09.lan
nameserver 192.168.13.254
nameserver 172.16.0.252
```

###### => si ip statique:
```
# nano /etc/network/interfaces
```
```
dns-nameservers 192.168.13.254 172.16.0.252
dns-search opti09.lan
```

###### => redémarrer le reseau ou reboot si besoin
```
# /etc/init.d/networking restart
```

```
# ping 192.168.13.254
# host srvdeb7.opti09.lan
# host DEBIAN-8-01.opti09.lan
```

###### 2- synchronisation du client linux au serveur temps:
```
# apt-get install ntp ntpdate
```
```
# nano /etc/ntp.conf
```
```
# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help

driftfile /var/lib/ntp/ntp.drift
logfile   /var/log/ntp


# Enable this if you want statistics to be logged.
#statsdir /var/log/ntpstats/

statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable


# You do need to talk to an NTP server or two (or three).
server srvdeb7.opti09.lan

# pool.ntp.org maps to about 1000 low-stratum NTP servers.  Your server will
# pick a different set every time it starts up.  Please consider joining the
# pool: <http://www.pool.ntp.org/join.html>
#server 0.debian.pool.ntp.org iburst
#server 1.debian.pool.ntp.org iburst
#server 2.debian.pool.ntp.org iburst
#server 3.debian.pool.ntp.org iburst


# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>
# might also be helpful.
#
# Note that "restrict" applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
#restrict -6 default kod notrap nomodify nopeer noquery

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
#restrict ::1

# Clients from this (example!) subnet have unlimited access, but only if
# cryptographically authenticated.
#restrict 192.168.123.0 mask 255.255.255.0 notrust

#server 3.debian.pool.ntp.org iburst

# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>
# might also be helpful.
#
# Note that "restrict" applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
#restrict -6 default kod notrap nomodify nopeer noquery

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
#restrict ::1

# Clients from this (example!) subnet have unlimited access, but only if
# cryptographically authenticated.
#restrict 192.168.123.0 mask 255.255.255.0 notrust


# If you want to provide time to your local subnet, change the next line.
# (Again, the address is an example only.)
#broadcast 192.168.123.255

# If you want to listen to time broadcasts on your local subnet, de-comment the
# next lines.  Please do this only if you trust everybody on the network!
disable auth
broadcastclient
```
```
# /etc/init.d/ntp restart
# ntpdate -q opti09.lan
# ntpq -pn
# ntptrace
# ntpq -p
```
###### (/!\ stratum = 3 ou 4/!\)

###### 3- installation de samba:
```
# apt-get install samba krb5-config krb5-user winbind libpam-winbind libnss-winbind
```
###### (/!\ renseigner si besoin le nom du domaine à Kerberos, en capitales = OPTI09.LAN /!\)

###### => tester l'authentification Kerberos:
```
# kinit Administrator
```
###### + pass admin AD
###### => afficher le ticket Kerberos:
```
# klist
```

###### => conf samba :
###### => copie de sauvegarde du fichier d'origine de la conf Samba:
```
# cp /etc/samba/smb.conf /etc/samba/smb.conf.initial
```
```
# nano /etc/samba/smb.conf
```
```
...
#======================= Global Settings =======================
                                                                      
[global]

## Browsing/Identification ###

# Change this to the workgroup/NT-domain name your Samba server will part of
   workgroup = OPTI09
        realm = OPTI09.LAN
        netbios name = DEBIAN-8-01
        security = ADS
        dns forwarder = 192.168.13.254
        idmap config * : backend = tdb
        idmap config *:range = 50000-1000000

        template homedir = /home/%D/%U
        template shell = /bin/bash
        winbind use default domain = true
        winbind offline logon = false
        winbind nss info = rfc2307
        winbind enum users = yes
        winbind enum groups = yes
        vfs objects = acl_xattr
        map acl inherit = Yes
        store dos attributes = Yes
...
```
###### => redemarrage des services Samba +:
```
# systemctl restart smbd nmbd winbind
# systemctl stop samba-ad-dc
# systemctl enable smbd nmbd winbind
```


###### 4- joindre la machine au domaine:
```
# net ads join -U Administrator
```
###### + pass admin AD
```
Joined 'DEBIAN-8-01' to dns domain 'opti09.lan'
```


###### 5- Conf de l'authentification des utilisateurs:

###### => conf NSS:
```
# nano /etc/nsswitch.conf
```
```
...
passwd:         compat winbind
group:          compat winbind
...
```
```
# reboot
```
###### => Check users groups:
```
# wbinfo -u
```
###### &
```
# wbinfo -g
```

###### => check authentification user AD:
```
# getent passwd| grep tata
```
###### => check Pam:
```
# pam-auth-update
```
###### + verifier que tout est coché + ok

###### => permettre l'authentification hors ligne:
```
# nano /etc/samba/smb.conf
```
```
...
winbind offline logon = yes
...
```
```
# nano /etc/security/pam_winbind.conf
```
```
[global]
# request a cached login if possible (needs "winbind offline logon = yes" in smb.conf)
cached_login = yes
```
```
# pam-auth-update
```
###### + vérifier que tout est coché + ok
```
# apt-get install nss-updatedb
# nss_updatedb winbind
# nano /etc/nsswitch.conf
```
```
...
passwd:         compat winbind db
group:          compat winbind db
...
```

###### /!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\
###### /!\ pour Clients DEBIAN: /!\
```
# nano /etc/pam.d/common-account
```
```
...
session    required    pam_mkhomedir.so    skel=/etc/skel/    umask=0022
```
###### /!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\
###### => permettre le changement de mot de passe par les utilisateur linux:
```
# nano /etc/pam.d/common-password
```
```
...
#password       [success=1 default=ignore]      pam_winbind.so use_authtok try_first_pass
...
password       [success=1 default=ignore]      pam_winbind.so try_first_pass
```

###### => check & creation du compte tata sur le client linux
```
# su - tata
```
###### => infos user tata +++:
```
$ id
$ pwd
```

###### => ajout de l'utilisateur tata aux privilèges sudo:
```
# sudo usermod -aG sudo tata
```

###### => ajout des privilèges root au groupe admins du domaine:
```
# visudo -f  /etc/sudoers
```
```
...
# User privilege specification
root    ALL=(ALL:ALL) ALL

%OPTI09\\opti09\admins  ALL=(ALL:ALL) ALL

...
```

###### => conf pour client linux avec interface graphique:
```
# cd /usr/share/lightdm/lightdm.conf.d/
# ls
```
```
01_debian.conf
```
```
# nano 01_debian.conf
```
```
...
greeter-show-manual-login=true
greeter-hide-users=true
```

######	      ===> REBOOT <===


###### => 1rst login Linux :
```	
   -> opti09\tata
   -> ou tata@opti09.lan
   -> ou tata
```
######   + pass tata



###### => check final => connexion avec un autre utilisateur du domaine...


######	Enjoy !

##	Active Directory Windows/Linux propulsed by Samba on Debian Server...

######	;)	
	
######	FM - GP3 - TSSI 27 - AFPA 83

######   :D	=>   https://www.youtube.com/watch?v=WixH03jx1jI
######   :p =>   https://www.youtube.com/watch?v=NUkpkc8cJmg
=============================================================================================

###### Sources Principales ==>
```
http://debian-facile.org/doc:reseau:dhcp
http://www.bidouilleit.com/2014/02/06/installation-configuration-et-administration-samba-4-ad/
https://dev.tranquil.it/wiki/SAMBA_-_Integration_avec_bind9
https://wiki.samba.org/index.php/Main_Page
https://wiki.samba.org/index.php/Configure_DHCP_to_update_DNS_records_with_BIND9
https://www.tecmint.com/manage-samba4-dns-group-policy-from-windows/
https://www.tecmint.com/join-ubuntu-to-active-directory-domain-member-samba-winbind/
```
