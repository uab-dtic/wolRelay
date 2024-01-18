#!/usr/bin/env python3

import logging
import getopt

import netifaces
from scapy.all import *
from wakeonlan import send_magic_packet


LISTEN_ON_DEVICE="eth0"
TARGET_ADDRESS="255.255.255.255"
TARGET_PORT=9
LOG_FILE=""
LOG_LEVEL="INFO"
WHO_CAN_SEND_WOL=[]

def show_help( error=0 ):
    logger.debug( "show_help")
    print( 
        "wolRelay", 
        "Forma de uso:",
        "    {} [-h] [-i device] [-t targetIp] [-r targetPort] [-w IPList][-l log file] [-v LOGLEVEL]".format( __file__ ),
        "",
        "   -h show this help.",
        "   -i Listen on device. Default {}.".format(LISTEN_ON_DEVICE),
        "   -t target ip. Default {}.".format(TARGET_ADDRESS) ,
        "   -r target port. Default {}.".format(TARGET_PORT),
        "   -w <lista de ips separadas por ,>",
        "   -l file_path",
        "   -v LEVEL. Default INFO.".format(LOG_LEVEL),
        "",
        "Variables de entorno:",
        "   LOGLEVEL=[DEBUG|INFO|WARNING|ERROR|CRITICAL] default=INFO",
        "",
        "Examples:",
        "     {} -h ".format( __file__ ),
        "     {} -i eth0".format( __file__ ),
        "     {} -t 192.168.1.100".format( __file__ ),
        "     {} -r 9000".format( __file__ ),
        "     {} -w '192.168.1.2,192.168.1.3".format( __file__),
        "     {} -l /var/log/wolRelay.log".format( __file__ ),
        "     {} -v DEBUG".format( __file__),
        "     LOGLEVEL=DEBUG {}".format(__file__),
        "",
        sep = "\n"
        )
    sys.exit( error )
    #


def get_local_ips():
    local_ips = []
    try:
        # Get a list of all network interfaces
        interfaces = netifaces.interfaces()

        # Iterate through each interface and get its addresses
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                # Get the IPv4 address if available
                ipv4_address = addresses[netifaces.AF_INET][0]['addr']
                local_ips.append(ipv4_address)
    except Exception as e:
        logger.debug(f"Error al obterner ip's locales: {e}")
    #

    return local_ips
# 

def sender_allowed( address):
    if len(WHO_CAN_SEND_WOL) > 0 and address not in WHO_CAN_SEND_WOL :
        logger.info(f"Sender {address} not allowed.")
        return False
    #
    logger.debug(f"Sender {address} allowed.")
    return True
#


def detectar_wol_paquetes(packet):
    #print ("Packet : '{}'".format(packet))

    if Ether in packet and IP in packet and UDP in packet and packet[UDP].dport == 9:
        # Verificar si es una trama de Wake-on-LAN
        wol_magic_bytes = b'\xff' * 6 #+ packet[Ether].dst * 16

        if packet[Raw].load.startswith(wol_magic_bytes):
            logger.debug(f"Trama Wake-on-LAN detectada:")

            wol_ip_from = packet[IP].src
            logger.debug(f"Dirección IP de origen: {wol_ip_from} {type(wol_ip_from)}")

            wol_ether_to = packet[Ether].dst
            logger.debug(f"Dirección MAC de destino: {wol_ether_to}")

            etherWol=""
            for x in range(6, 6+5):
                #print ("i({})->{}".format(x, packet[Raw].load[x]))
                etherWol = etherWol + format(packet[Raw].load[x],'02x') + ":"
            etherWol = etherWol + format( packet[Raw].load[6+5], '02x')

            logger.debug(f"EtherWol: {etherWol}")

            if wol_ip_from not in local_ip_list :
                if sender_allowed( wol_ip_from) :
                    logger.info( "wol to '{}' from remote ip. resend to '{}:{}'".format(etherWol, TARGET_ADDRESS, TARGET_PORT) )
                    send_magic_packet( etherWol, ip_address=TARGET_ADDRESS, port=TARGET_PORT )
                #
            else:
                logger.debug( "wol from local ip")
            #
        #
    #
#


if __name__ == '__main__':
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)s] - %(message)s")
    logger = logging.getLogger()

    LOGLEVEL = os.environ.get('LOGLEVEL','INFO')
    
    try :
        logger.setLevel(LOGLEVEL)
    except:
        logger.critical( "LOGLEVEL ERROR ON ID '{}'".format(LOGLEVEL))
        show_help(3)
    #

    log = logging.getLogger( __name__ )

    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)

    try:
        opts, args = getopt.getopt(sys.argv[1:],'hi:t:r:w:l:v:')
    except getopt.GetoptError:
        logger.critical("Error on options")        
        show_help( 2 )
    
    logger.debug( "opts: {}".format( opts))
    logger.debug( "args: {}".format( args))

    for opt, arg in opts:
        if opt == '-h':
            show_help( 0 )

        elif opt == '-i':
            LISTEN_ON_DEVICE = arg
            logger.debug( "Set new Sniff on device: {}".format( LISTEN_ON_DEVICE ))

        elif opt == '-t':
            TARGET_ADDRESS = arg
            logger.debug( "Set new TARGET Address:{}".format( TARGET_ADDRESS ))

        elif opt == '-r':
            TARGET_PORT = int( arg )
            logger.debug( "Set new TARGET Port:{}".format( TARGET_PORT ))

        elif opt == '-w':
            WHO_CAN_SEND_WOL = arg.split(",")
            logger.debug( "Set new Senders allowed: '{}'".format( WHO_CAN_SEND_WOL ))

        elif opt == "-l":
            LOG_FILE = arg
            logger.debug( "Set new Log File:{}".format( LOG_FILE ))

            fileHandler = logging.FileHandler( LOG_FILE )
            fileHandler.setFormatter(logFormatter)
            logger.addHandler(fileHandler)

        elif opt == '-v':
            LOGLEVEL = arg
            try :
                logger.setLevel(LOGLEVEL)
                logger.debug( "Set new LOGLEVEL:{}".format( LOGLEVEL ))
            except:
                logger.critical( "LOGLEVEL ERROR ON ID '{}'".format(LOGLEVEL))
                show_help(3)
            #
        #
    #
    # Show configuration by default
    logger.info( "Sniff on device: {}".format( LISTEN_ON_DEVICE ))
    logger.info( "TARGET Address:{}".format( TARGET_ADDRESS ))
    logger.info( "TARGET Port:{}".format( TARGET_PORT ))
    logger.info( "Senders allowed; '{}'".format( WHO_CAN_SEND_WOL ))
    logger.info( "Log File:{}".format( LOG_FILE ))
    logger.info( "LOG LEVEL:{}".format( LOGLEVEL ))

    # Get Local IP's
    local_ip_list = get_local_ips()

    logger.debug (f"Local IP's {local_ip_list}")

    try:
        # Sniff para paquetes en la interfaz específica (puedes cambiar 'eth0' por tu interfaz)
        sniff(iface=LISTEN_ON_DEVICE, prn=detectar_wol_paquetes, store=0, filter='udp')
    except Exception as e:
        log.critical("Error on sniff: '{}' ".format( type(e).__name__ ))
        show_help (1)
    #

# END
