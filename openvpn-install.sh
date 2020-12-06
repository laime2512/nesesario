#!/bin/bash
#
# https://cubaelectronica.com/OpenVPN/openvpn-install
#
# Traducido al Español por CubaElectronica
#
# Copyright (c) 2020 CubaElectronica. Released under the MIT License.


# Detectar usuarios de Debian que ejecutan el script con "sh" en lugar de bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "Este script debe ejecutarse con bash, no sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Lo siento, necesitas ejecutar esto como root"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "El dispositivo TUN no está disponible
	Debe habilitar TUN antes de ejecutar este script"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Parece que no está ejecutando este instalador en Debian, Ubuntu o CentOS"
	exit
fi

newclient () {
	# Generar el cliente personalizado client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Parece que OpenVPN ya está instalado."
		echo
		echo "Qué quieres hacer?"
		echo "   1) Agregar nuevo usuario"
		echo "   2) Eliminar usuario existente"
		echo "   3) Desintalar OpenVPN"
		echo "   4) Salir"
		read -p "Selecciona una opción [1-4]: " option
		case $option in
			1) 
			echo
			echo "Dime un nombre para el certificado del cliente."
			echo "Por favor, use solo una palabra, sin caracteres especiales."
			read -p "Nombre del Cliente: " -e CLIENT
			cd /etc/openvpn/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
			# Generar el cliente personalizado client.ovpn
			newclient "$CLIENT"
			echo
			echo "Cliente $CLIENT agregado, la configuración está disponible en:" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# Esta opción podría documentarse un poco mejor y tal vez incluso simplificarse!!
		    NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo
				echo "No tienes clientes existentes!"
				exit
			fi
			echo
			echo "Seleccione el certificado de cliente existente que desea remover:"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Seleccione un cliente [1]: " CLIENTNUMBER
			else
				read -p "Seleccione un cliente [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			echo
			read -p "Realmente esta seguro de eliminar el cliente $CLIENT? [y/N]: " -e REVOKE
			if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				# CRL se lee con cada conexión de cliente, cuando OpenVPN se deja caer a nadie
				chown nobody:$GROUPNAME /etc/openvpn/crl.pem
				echo
				echo "Certificado para el cliente $CLIENT eliminado!"
			else
				echo
				echo "Certificado para el cliente $CLIENT abortado!"
			fi
			exit
			;;
			3) 
			echo
			read -p "¿Realmente quieres eliminar OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Usar reglas permanentes y no permanentes para evitar una recarga de Firewall.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				echo
				echo "OpenVPN eliminado!"
			else
				echo
				echo "Eliminar abortado!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Bienvenido a este instalador de OpenVPN "by CubaElectronica"!'
	echo
	# OpenVPN configuración y creación del primer usuario
	echo "Necesito hacerte algunas preguntas antes de comenzar la configuración.."
	echo "Puede dejar las opciones predeterminadas y simplemente presionar Enter si está de acuerdo con ellas."
	echo
	echo "Primero, proporcione la dirección IPv4 de la interfaz de red que desea OpenVPN"
	echo "Escuchando de."
	# Autodetect IP address and pre-fill for the user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Este servidor está detrás de NAT. ¿Cuál es la dirección IPv4 pública o el nombre de host?"
		read -p "Dirección IP pública / o hostname: " -e PUBLICIP
	fi
	echo
	echo "¿Qué protocolo quieres para las conexiones OpenVPN?"
	echo "   1) UDP (recomendado)"
	echo "   2) TCP"
	read -p "Protocolo [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "¿Qué puerto quieres que escuche OpenVPN?"
	read -p "Puerto: " -e -i 1194 PORT
	echo
	echo "¿Qué DNS quieres usar con la VPN?"
	echo "   1) Del sistema actual"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 3 DNS
	echo
	echo "Finalmente, dígame el nombre para el certificado de cliente."
	echo "Por favor, use solo una palabra, sin caracteres especiales."
	read -p "Nombre del Cliente: " -e -i client CLIENT
	echo
	echo "De acuerdo, eso era todo lo que necesitaba. Estamos listos para configurar su servidor OpenVPN ahora. ESTO TENDRÁ ALGÚN TIEMPO"
	read -n1 -r -p "Pulse cualquier tecla para continuar..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# De lo contrario, la distribución es CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Obtener easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v3.0.6.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-v3.0.6/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-v3.0.6/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/
	# Cree la PKI, configure la CA y los certificados de servidor y cliente, POR 3650 DÍAS
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Mueve las cosas que necesitamos
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# CRL se lee con cada conexión de cliente, cuando OpenVPN se deja caer a nadie
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generar clave para tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Generando los parámetros DH
	openssl dhparam -out /etc/openvpn/dh2048.pem 2048
	# Generar server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Localice el adecuado resolv.conf
		# Necesario para sistemas en ejecución systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtenga los resolutores de resolv.conf y utilícelos para OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Habilite net.ipv4.ip_forward para el sistema
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Habilitar sin esperar un reinicio o reinicio del servicio
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Usar reglas permanentes y no permanentes para evitar un cortafuegos
		# recargar.
		# No usamos --add-service = openvpn porque eso solo funcionaría con
		# el puerto y el protocolo predeterminados.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Configurar NAT para la subred VPN
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		# Necesitaba usar rc.local con algunas distribuciones systemd
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Configurar NAT para la subred VPN
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# Si iptables tiene al menos una regla REJECT, asumimos que es necesaria.
			# No es el mejor enfoque, pero no puedo pensar en otro y este no debería
			# dar problemas.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# Si SELinux está habilitado y se seleccionó un puerto personalizado, necesitamos esto
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Instale semanage si aún no está presente
		if ! hash semanage 2>/dev/null; then
			yum install policycoreutils-python -y
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# Y finalmente, reinicia OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Pequeño truco para verificar systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Si el servidor está detrás de un NAT, use la dirección IP correcta
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# Se crea client-common.txt, por lo que tenemos una plantilla para agregar más usuarios más tarde
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Genera el client.ovpn personalizado
	newclient "$CLIENT"
	echo
	echo "Terminado!"
	echo
	mv ~/"$CLIENT.ovpn" /home/"$CLIENT.ovpn"
	echo "La configuración de su cliente está disponible en:" /home/"$CLIENT.ovpn"
	echo "Si desea agregar más clientes, simplemente debe ejecutar este script nuevamente ('sudo bash openvpn-install.sh')!"
fi
