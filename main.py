import select, socket
import sys
import os
import logging, logging.handlers
import daemon
import lockfile
import signal
from rawpacket import RawPacket, UnmatchedGenevePort
import config
import argparse
from flow_tracker import FlowTracker
import setproctitle


LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

logger = None
prog_break = False


def shutdown(signum, sigframe):
    global logger
    global prog_break
    logger.info(f"Received signal {signum}")
    prog_break = True


def cli_parser():
    parser = argparse.ArgumentParser(
        prog="geneve-router",
        description="Geneve router for AWS GWLB",
        epilog="by Antho Balitrand"
    )

    parser.add_argument(
        "--no-daemon",
        action="store_true",
        help="Do not start the Geneve router as a daemon",
    )

    parser.add_argument(
        "-l", "--log-level",
        action="store",
        help=f"Log level. If used without --no-daemon, will force logging to {config.LOG_FILE}",
        default="default"
    )

    parser.add_argument(
        "-f", "--log-file",
        action="store",
        help="Logging file. Overwrites the config.LOG_FILE parameter",
        default=config.LOG_FILE
    )

    parser.add_argument(
        "-t", "--flow-tracker",
        action="store_true",
        help="Enables flow tracker, which provides only start/stop flow logging information"
    )

    return parser.parse_args()


def check_permission():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        sys.exit('Please start with root permissions')


def start(start_cli_args):
    global logger
    global prog_break

    logger.info(f"Start with PID {os.getpid()}")

    flow_tracker = None
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

    if start_cli_args.flow_tracker:
        logger.info("Starting flow tracker...")
        flow_tracker = FlowTracker(logger)

    while True and not prog_break:
        try:
            # last parameter for select.select is a timeout which makes it non-blocking
            # without this parameter, the function is blocking until there's one socket ready
            read_sockets, _, _ = select.select(sockets, [], [], 10)
            for s_sock in read_sockets:
                if s_sock == main_socket:
                    data, addr = s_sock.recvfrom(65584)
                    logger.debug(f"GENEVE - Received packet from {addr[0]}")
                    if (geneve_response_packet := geneve_handler(data, flow_tracker)):
                        s_sock.sendto(geneve_response_packet, addr)
                        logger.debug(f"GENEVE - Packet forwarded")
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
                    _, _ = s_sock.recvfrom(65536)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Unexpected error : {e}")

    logger.warning("Exit requested. Closing sockets...")
    health_socket.close()
    main_socket.close()
    bind_socket.close()

    logger.warning("Bye bye")


def main():
    start_cli_args = cli_parser()
    check_permission()

    print("Starting and initializing logger...")
    global logger
    logger, h = configure_logging(
        config.LOG_LEVEL if start_cli_args.log_level == "default" else start_cli_args.log_level,
        "geneve-router",
        logfile=start_cli_args.log_file,
        on_screen=start_cli_args.no_daemon,
        force_logging=True if start_cli_args.log_level != "default" else False
    )

    if start_cli_args.no_daemon:
        start(start_cli_args)
    else:
        with daemon.DaemonContext(
            pidfile=lockfile.FileLock('/var/run/geneve-router.pid'),
            signal_map={
                signal.SIGTERM: shutdown,
                signal.SIGTSTP: shutdown
            },
            working_directory=os.getcwd(),
            files_preserve=[h.stream]
        ) as d:
            setproctitle.setproctitle('geneve-router')
            start(start_cli_args)
            d.join()

    return 0


def configure_logging(level, loggername, logfile, on_screen=True, force_logging=False):
    global logger
    logger = logging.getLogger(loggername)
    logger.setLevel(LOG_LEVELS.get(level, LOG_LEVELS["debug"]))
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    h = None
    if not on_screen and force_logging:
        h = logging.handlers.WatchedFileHandler(logfile)
        h.setLevel(LOG_LEVELS.get(level, LOG_LEVELS["debug"]))
        h.setFormatter(formatter)
        logger.addHandler(h)
    elif on_screen:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(formatter)
        logger.addHandler(h)
    return logger, h


def http_healthcheck_response():
    body = "Healthy\n"

    header = f"HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: {len(body)}\nConnection: close"
    return header + '\n\n' + body


def geneve_handler(geneve_packet, flow_tracker):
    global logger
    try:
        rec_packet = RawPacket(logger, geneve_packet, flow_tracker)
    except UnmatchedGenevePort:
        logger.debug("Ignoring packet received on non-Geneve port")
        return None
    except Exception as e:
        logger.error(f"Unknown error while parsing new packet : {e}")
        return None
    return rec_packet.resp


if __name__ == "__main__":
    main()