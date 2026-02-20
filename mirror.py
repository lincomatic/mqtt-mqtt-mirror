import asyncio
import configparser
import logging
from pathlib import Path
import platform
import random
import ssl
import sys
import aiomqtt


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)
logger.info("Script starting, loading configuration...")

# Map protocol string to aiomqtt protocol version
protocol_map = {
    "v5": 5,
    "v311": 4,
    "v31": 3,
    "5": 5,
    "3.1.1": 4,
    "3.1": 3,
}

def load_config():
    parser = configparser.ConfigParser()
    config_path = Path(__file__).with_name("mirror.ini")
    logger.info("Looking for config file at: %s", config_path.absolute())
    if not config_path.exists():
        logger.error("Config file not found at %s", config_path.absolute())
        raise FileNotFoundError(f"mirror.ini not found at {config_path.absolute()}")
    parser.read(config_path, encoding="utf-8")
    logger.debug("Config file read, sections found: %s", parser.sections())

    global_cfg = parser["global"] if parser.has_section("global") else None
    if not parser.has_section("local"):
        raise KeyError("Required section [local] not found in mirror.ini")
    local = parser["local"]
    logger.debug("Parsed [global] and [local] sections")
    log_level = global_cfg.get("log_level", "INFO") if global_cfg else "INFO"
    test_mode = parser.getboolean("global", "test", fallback=False)
    test_topic = global_cfg.get("test_topic", "test") if global_cfg else "test"
    test_topic = test_topic.strip("\"'")

    remotes = []
    for section_name in parser.sections():
        if not section_name.lower().startswith("remote"):
            continue
        remote = parser[section_name]
        remote_enabled = remote.getboolean("enable", fallback=False)

        # Validate required parameters
        remote_host = remote.get("host")
        if not remote_host:
            raise KeyError(f"[{section_name}] Required parameter 'host' is missing")
        if not remote.get("port"):
            raise KeyError(f"[{section_name}] Required parameter 'port' is missing")
        remote_port = remote.getint("port")

        remote_qos = remote.getint("qos", fallback=0)
        if remote_qos not in (0, 1, 2):
            raise ValueError(f"[{section_name}] Invalid qos={remote_qos}, must be 0, 1, or 2")

        remote_use_tls = remote.getboolean("use_tls", fallback=False)
        remote_tls_insecure = remote.getboolean("tls_insecure", fallback=False)
        remote_use_websockets = remote.getboolean("use_websockets", fallback=False)
        remote_session_expiry = remote.getint("session_expiry", fallback=0)
        remote_retry_interval = remote.getint("retry_interval", fallback=15)
        remote_keepalive = remote.getint("keepalive", fallback=60)

        remote_protocol_str = remote.get("protocol", "v311").lower()
        remote_protocol = protocol_map.get(remote_protocol_str, 4)
        
        remote_topics = [(topic.strip(), remote_qos) for topic in remote.get("topics", "").split(",") if topic.strip()]
        if remote_enabled and not remote_topics:
            raise ValueError(f"[{section_name}] Enabled remote has no topics configured")

        remotes.append(
            {
                "name": section_name,
                "enabled": remote_enabled,
                "host": remote_host,
                "port": remote_port,
                "user": remote.get("user"),
                "password": remote.get("pass"),
                "qos": remote_qos,
                "use_tls": remote_use_tls,
                "tls_insecure": remote_tls_insecure,
                "use_websockets": remote_use_websockets,
                "session_expiry": remote_session_expiry,
                "retry_interval": remote_retry_interval,
                "keepalive": remote_keepalive,
                "protocol": remote_protocol,
                "protocol_str": remote_protocol_str,
                "topics": remote_topics,
            }
        )

    # Validate at least one enabled remote exists
    if not any(r["enabled"] for r in remotes):
        raise ValueError("No enabled [remote*] sections found in mirror.ini. "
                         "At least one remote must have enable=true")

    # Validate local required parameters
    local_host = local.get("host")
    if not local_host:
        raise KeyError("[local] Required parameter 'host' is missing")
    if not local.get("port"):
        raise KeyError("[local] Required parameter 'port' is missing")
    local_port = local.getint("port")

    return {
        "REMOTES": remotes,
        "GLOBAL_LOG_LEVEL": log_level,
        "GLOBAL_TEST": test_mode,
        "GLOBAL_TEST_TOPIC": test_topic,
        "LOCAL_HOST": local_host,
        "LOCAL_PORT": local_port,
        "LOCAL_USE_TLS": local.getboolean("use_tls", fallback=False),
        "LOCAL_TLS_INSECURE": local.getboolean("tls_insecure", fallback=False),
        "LOCAL_USE_WEBSOCKETS": local.getboolean("use_websockets", fallback=False),
        "LOCAL_USER": local.get("user"),
        "LOCAL_PASS": local.get("pass"),
        "LOCAL_KEEPALIVE": local.getint("keepalive", fallback=60),
        "LOCAL_RETRY_INTERVAL": local.getint("retry_interval", fallback=15),
        "LOCAL_PROTOCOL_STR": local.get("protocol", "v311").lower()
    }


try:
    settings = load_config()
    logger.info("Config loaded successfully")
    REMOTES = settings["REMOTES"]
    GLOBAL_LOG_LEVEL = settings["GLOBAL_LOG_LEVEL"]
    GLOBAL_TEST = settings["GLOBAL_TEST"]
    GLOBAL_TEST_TOPIC = settings["GLOBAL_TEST_TOPIC"]
    LOCAL_HOST = settings["LOCAL_HOST"]
    LOCAL_PORT = settings["LOCAL_PORT"]
    LOCAL_USE_TLS = settings["LOCAL_USE_TLS"]
    LOCAL_TLS_INSECURE = settings["LOCAL_TLS_INSECURE"]
    LOCAL_USE_WEBSOCKETS = settings["LOCAL_USE_WEBSOCKETS"]
    LOCAL_USER = settings["LOCAL_USER"]
    LOCAL_PASS = settings["LOCAL_PASS"]
    LOCAL_KEEPALIVE = settings["LOCAL_KEEPALIVE"]
    LOCAL_RETRY_INTERVAL = settings["LOCAL_RETRY_INTERVAL"]
    LOCAL_PROTOCOL_STR = settings["LOCAL_PROTOCOL_STR"]
    logger.info("Loaded %d remote broker config(s)", len(REMOTES))
    resolved_log_level = getattr(logging, str(GLOBAL_LOG_LEVEL).upper(), logging.INFO)
    logging.getLogger().setLevel(resolved_log_level)
    logger.setLevel(resolved_log_level)
    logger.info("Log level set to: " + str(GLOBAL_LOG_LEVEL).upper())
except Exception as e:
    logger.error("Failed to load configuration: %s", e, exc_info=True)
    raise


async def mirror_remote_broker(remote_cfg, local_client):
    """Connect to a remote broker and mirror its messages to the local broker with automatic reconnection."""
    remote_name = remote_cfg["name"]
    logger.debug("[%s] mirror_remote_broker task started", remote_name)
    
    if not remote_cfg["enabled"]:
        logger.info("[%s] Disabled by config (enable=false), skipping connection", remote_name)
        return

    client_id = f"mqtt{remote_name}{random.randint(1000000, 9999999)}"
    while True:  # Infinite reconnection loop
        try:
            logger.info(
                "[%s] Generated client ID: %s, protocol: %s, use_websockets: %s",
                remote_name,
                client_id,
                remote_cfg['protocol_str'],
                remote_cfg['use_websockets']
            )
            logger.debug("[%s] Connecting to %s:%s", remote_name, remote_cfg['host'], remote_cfg['port'])
            
            # Build TLS parameters if needed (always needed when use_tls=true, even if insecure)
            tls_params = None
            if remote_cfg["use_tls"]:
                tls_params = aiomqtt.TLSParameters(
                    ca_certs=None,
                    certfile=None,
                    keyfile=None,
                    cert_reqs=ssl.CERT_NONE if remote_cfg["tls_insecure"] else ssl.CERT_REQUIRED,
                    ciphers=None
                )

            async with aiomqtt.Client(
                hostname=remote_cfg["host"],
                port=remote_cfg["port"],
                protocol=aiomqtt.ProtocolVersion(remote_cfg["protocol"]),
                username=remote_cfg["user"],
                password=remote_cfg["password"],
                identifier=client_id,
                keepalive=remote_cfg["keepalive"],
                clean_session=(remote_cfg["session_expiry"] == 0),
                transport="websockets" if remote_cfg["use_websockets"] else "tcp",
                tls_params=tls_params,
            ) as client:
                logger.info("[%s] Connected to %s:%s", remote_name, remote_cfg['host'], remote_cfg['port'])
                
                # Subscribe to all configured topics
                for topic, qos in remote_cfg["topics"]:
                    await client.subscribe(topic, qos)
                    logger.info("[%s] Subscribed to %s (qos=%d)", remote_name, topic, qos)
                
                # Listen for messages
                async for message in client.messages:
                    # Convert topic to string if needed
                    msg_topic = str(message.topic)
                    logger.debug(
                        "[%s] Received message on %s (qos=%d, retain=%s, payload_size=%d bytes)",
                        remote_name,
                        msg_topic,
                        message.qos,
                        message.retain,
                        len(message.payload)
                    )
                    
                    try:
                        # Build target topic with test prefix if needed
                        if GLOBAL_TEST:
                            test_prefix = GLOBAL_TEST_TOPIC.strip().rstrip("/")
                            target_topic = f"{test_prefix}/{msg_topic}" if test_prefix else msg_topic
                        else:
                            target_topic = msg_topic
                        
                        logger.debug("[LOCAL] Publishing to %s", target_topic)
                        await local_client.publish(
                            target_topic,
                            message.payload,
                            qos=message.qos,
                            retain=message.retain
                        )
                    except Exception as e:  # pylint: disable=broad-except
                        logger.error("[LOCAL] Publish exception: %s", e)

        except aiomqtt.MqttError as e:
            logger.error(
                "[%s] MQTT error: %s. Retrying in %ds...",
                remote_name,
                e,
                remote_cfg['retry_interval'],
                exc_info=True
            )
            await asyncio.sleep(remote_cfg['retry_interval'])
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "[%s] Unexpected error: %s. Retrying in %ds...",
                remote_name,
                e,
                remote_cfg['retry_interval'],
                exc_info=True
            )
            await asyncio.sleep(remote_cfg['retry_interval'])


async def main():
    """Main coroutine that manages local broker connection and remote mirror tasks."""
    logger.debug("[CONFIG] Remotes loaded: %d", len(REMOTES))
    for remote in REMOTES:
        logger.debug(
            "[CONFIG] Remote '%s': enabled=%s, host=%s, port=%s",
            remote['name'],
            remote['enabled'],
            remote['host'],
            remote['port']
        )
    
    logger.info(
        "[CONFIG] global.log_level=%s test=%s test_topic=%s",
        str(GLOBAL_LOG_LEVEL).upper(),
        str(GLOBAL_TEST).lower(),
        GLOBAL_TEST_TOPIC
    )
    logger.info(
        "[local] protocol=%s use_tls=%s tls_insecure=%s use_websockets=%s keepalive=%d retry_interval=%d",
        LOCAL_PROTOCOL_STR,
        str(LOCAL_USE_TLS).lower(),
        str(LOCAL_TLS_INSECURE).lower(),
        str(LOCAL_USE_WEBSOCKETS).lower(),
        LOCAL_KEEPALIVE,
        LOCAL_RETRY_INTERVAL
    )
    logger.info("[CONFIG] Loaded remote topic subscriptions:")
    for remote in REMOTES:
        logger.info(
            "[%s] enable=%s protocol=%s use_tls=%s tls_insecure=%s use_websockets=%s session_expiry=%d retry_interval=%d keepalive=%d",
            remote['name'],
            str(remote['enabled']).lower(),
            remote['protocol_str'],
            str(remote['use_tls']).lower(),
            str(remote['tls_insecure']).lower(),
            str(remote['use_websockets']).lower(),
            remote['session_expiry'],
            remote['retry_interval'],
            remote['keepalive']
        )
        if remote["enabled"]:
            logger.info("[%s] Topics:", remote['name'])
            for topic, qos in remote["topics"]:
                logger.info("[%s] - %s (qos=%d)", remote['name'], topic, qos)
        else:
            logger.info("[%s] Skipping topics because broker is disabled", remote['name'])

    # Build TLS parameters for local broker if needed (always needed when use_tls=true, even if insecure)
    local_tls_params = None
    if LOCAL_USE_TLS:
        local_tls_params = aiomqtt.TLSParameters(
            ca_certs=None,
            certfile=None,
            keyfile=None,
            cert_reqs=ssl.CERT_NONE if LOCAL_TLS_INSECURE else ssl.CERT_REQUIRED,
            ciphers=None
        )

    local_client_id = f"mqttmirror{random.randint(1000000, 9999999)}"
    while True:
        try:
            logger.info("[LOCAL] Trying to connect to Mosquitto at %s:%s", LOCAL_HOST, LOCAL_PORT)
            async with aiomqtt.Client(
                hostname=LOCAL_HOST,
                port=LOCAL_PORT,
                protocol=aiomqtt.ProtocolVersion(protocol_map.get(LOCAL_PROTOCOL_STR, 4)),
                username=LOCAL_USER,
                password=LOCAL_PASS,
                identifier=local_client_id,
                keepalive=LOCAL_KEEPALIVE,
                transport="websockets" if LOCAL_USE_WEBSOCKETS else "tcp",
                tls_params=local_tls_params,
            ) as local_client:
                logger.info("[LOCAL] Connected to Mosquitto at %s:%s", LOCAL_HOST, LOCAL_PORT)
                
                # Create concurrent tasks for all enabled remote brokers
                logger.debug("[LOCAL] Creating tasks for %d remote(s)", len(REMOTES))
                remote_tasks = [
                    asyncio.create_task(mirror_remote_broker(remote, local_client))
                    for remote in REMOTES
                ]
                logger.debug("[LOCAL] Created %d task(s), starting to gather", len(remote_tasks))
                
                # Run all remote mirror tasks concurrently
                # If any task fails, we'll catch the exception and reconnect
                results = await asyncio.gather(*remote_tasks, return_exceptions=True)
                logger.debug("[LOCAL] Gather completed with results: %s", results)
                
        except aiomqtt.MqttError as e:
            logger.error(
                "[LOCAL] MQTT error: %s. Retrying in %ds...",
                e,
                LOCAL_RETRY_INTERVAL,
                exc_info=True
            )
            await asyncio.sleep(LOCAL_RETRY_INTERVAL)
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "[LOCAL] Unexpected error: %s. Retrying in %ds...",
                e,
                LOCAL_RETRY_INTERVAL,
                exc_info=True
            )
            await asyncio.sleep(LOCAL_RETRY_INTERVAL)


if __name__ == "__main__":
    try:
        # On Windows, aiomqtt requires SelectorEventLoop, not ProactorEventLoop
        # Import explicitly to avoid linter errors
        if sys.platform.lower() == "win32" or platform.system() == "Windows":
            from asyncio import set_event_loop_policy, WindowsSelectorEventLoopPolicy
            set_event_loop_policy(WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Fatal error in main: %s", e, exc_info=True)
        raise
