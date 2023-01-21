import select, socket
import sys
import logging, logging.handlers
import signal
from rawpacket import RawPacket, UnmatchedGenevePort
import config

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logger = None

def main():
    print("Starting and initializing logger...")
    global logger
    logger = configure_logging("debug", "geneve-router")

    logger.info("Logging initialized. Building sockets...")

    # the health_socket is the one used for the GWLB health-check requests
    health_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    health_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    health_socket.bind(('0.0.0.0', config.HEALTH_CHECK_PORT))
    health_socket.listen(3)

    # the bind_socket is only used to "announce" that we want to receive UDP datagrams for GENEVE_PORT
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_socket.bind(('0.0.0.0', config.GENEVE_PORT))

    # the main_socket is the one used to receive the Geneve packets
    main_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    # IP_HDRINCL permits to ask the system that we want to receive (and create) our own IP/UDP headers
    # this is needed as Geneve requires that we send back the "routed" traffic on the GENEVE_PORT (src/dst ports
    # are not swapped)
    main_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    main_socket.bind(('0.0.0.0', config.GENEVE_PORT))

    sockets = [main_socket, bind_socket, health_socket]
    logger.info("Sockets are ready. Listening...")

    while True:
        try:
            read_sockets, _, _ = select.select(sockets, [], [])
            for s_sock in read_sockets:
                if s_sock == main_socket:
                    data, addr = s_sock.recvfrom(65565)
                    logger.debug(f"GENEVE - Received packet from {addr[0]}")
                    if (geneve_response_packet := geneve_handler(data)):
                        s_sock.send(geneve_response_packet)
                if s_sock == health_socket:
                    c_sock, c_addr = s_sock.accept()
                    c_sock.settimeout(1.0)
                    try:
                        c_sock.recv(1024)
                        logger.debug(f"HEALTH-CHECK - Received request from {c_addr[0]}:{c_addr[1]}")
                        c_sock.send(http_healthcheck_response().encode('utf-8'))
                    except socket.timeout:
                        logger.warning(f"HEALTH-CHECK - Timeout raised on socket from {c_addr[0]}:{c_addr[1]}")
                    finally:
                        c_sock.close()
                if s_sock == bind_socket:
                    data, addr = s_sock.recvfrom(65565)
                    #print(f"BIND SOCK - received from {addr} : {data.decode('utf-8')}")
        except KeyboardInterrupt:
            logger.warning("User-interrupt received. Closing sockets...")
            health_socket.close()
            main_socket.close()
            bind_socket.close()
            break

    return 0

def configure_logging(level, loggername, logfile="logging.log", on_screen=True):
    logger = logging.getLogger(loggername)
    logger.setLevel(LOG_LEVELS.get(level, LOG_LEVELS["debug"]))
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if not on_screen:
        fh = logging.handlers.WatchedFileHandler(logfile)
        fh.setLevel(LOG_LEVELS.get(level, LOG_LEVELS["debug"]))
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    else:
        sh = logging.StreamHandler(stream=sys.stdout)
        sh.setFormatter(formatter)
        logger.addHandler(sh)
    return logger

def http_healthcheck_response():
    body = "Healthy\n"

    header = f"HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: {len(body)}\nConnection: close"
    return header + '\n\n' + body

def geneve_handler(geneve_packet):
    global logger
    try:
        rec_packet = RawPacket(logger, geneve_packet)
    except UnmatchedGenevePort:
        logger.debug("Ignoring UDP packet receive on non-Geneve port")
        return None
    return None

if __name__ == "__main__":
    main()