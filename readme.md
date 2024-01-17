# Wake On Lan Relay Server

Este servidor esnifa un dispositivo de red, para detectar tramas de WoL **en la red local** y reenviarlas.

Este servidor solo tiene sentido en routers con varias interficies donde los paquetes de WoL generados en la red local no pasan a la red externa.

## Dependencias

Necesitaremos tener instalados algunos paquetes.

- python3-venv : Para crear el entorno virtual de python
- python3-dev  : Para poder realizar la instalacion de los _requisites_
- libpcap0.8   : Para poder realizar el _sniffing_

## instalación/configuracion

La configuracioón se puede realizar con cualquier usuario que tenga permisos para escribir en el directorio de destino, pero la ejecución se debe realizar con el usuario **root** ya que necesita permisos para poder poner la tarjeta de red en modo promiscuo

Vamos a suponer que tenemos el codigo en el directorio /opt/wolrelay.Si descargamos desde un repositorio de git lo podemos hacer directamente con el comando

Direccion del repositorio:

- https: https://github.com/uab-dtic/wolRelay.git
- ssh: git@github.com:uab-dtic/wolRelay.git"

```bash
git clone {REPOSITORIO} /opt/wolRelay
```

Creamos el entorno virtual

```bash
cd /opt/wolrelay
python -m venv env
. env/bin/activate
```

En este punto en el prompt debemos ver que estamos en un entorno virtual

```data
(env) root@sab-sid02:/opt/wolrelay #
```

Añadimos las dependencias

```bash
(env) root:/opt/wolrelay # pip3 install -r requirements.txt
```

## Forma de uso desde linea de comandos

Si necesitamos que el entorno virtual quede persistente necesitamos activarlo

```bash
root@localhost:~# cd /opt/wolrelay
root@localhost:/opt/wolrelay# . env/bin/activate
(env) root@localhost:/opt/wolrelay# ./wolRelay -h
wolRelay
Forma de uso:
    /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py [-h] [-i device]  [-l log file] [ -t IP] [-r port]

   -h show this help.
   -i Listen on device. Default eth0.
   -t target ip. Default 255.255.255.255.
   -r target port. Default 9.


Variables de entorno:
   LOGLEVEL=[DEBUG|INFO|WARNING|ERROR|CRITICAL] default=INFO

Examples:
     /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py -h 
     /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py -i eth0
     /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py -l /var/log/wol_replicator.log
     /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py -t 192.168.1.100
     /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py -r 9000
     LOGLEVEL=DEBUG /home/jroman/_SID_SBD_/wolRelay/./wolRelay.py

```

Si queremos ejecutarlo sin un entorno virtual persistente

```bash

root@localhost:~ # /opt/wolRelay/env/bin/python /opt/wolRelay/wolRelay.py -h
...

```

## Forma de uso desde systemd

Copiar o hacer un link del fichero wolRelay.service a /etc/systemd/system/

```bash
sudo ln -s /opt/wolRelay/wolRelay.service /etc/systemd/system/wolRelay.service
```

Modificar el fichero **/opt/wolRelay/wolRelay.conf** con las opciones apropiadas

Habilitar el servicio para que arranque tras un reinicio

```bash
sudo systemctl enable wolRelay
```

Arrancar el servicio manualmente

```bash
sudo systemctl start wolRelay
```

Comprobar el estadodel servicio

```bash
sudo systemctl status wolRelay
```

## configuraciones adicionales

Hay que tener en cuenta el fichero de log que se genere y configurar el logrotate para que no se llene el disco inecesariamente

Por ejemplo podemos añadir el siguiente **/etc/logrotate.d/wolRelay**

```data
/var/log/wolRelay.log {

    daily
    rotate 2
    compress

    delaycompress
    missingok

    postrotate
        systemctl restart wolRelay
    endscript
}
```

(Copyright 2024 JRM SID-SABADELL)