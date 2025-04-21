import logging
import graypy

# Create a logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)  # You can adjust this based on your needs

# Set up Graylog logging handler
handler = graypy.GELFUDPHandler('192.168.196.128', 12201)  # Graylog server IP and UDP port (default 12201)
logger.addHandler(handler)

# Test logging
logger.info("This is an informational message")
logger.warning("This is a warning message")
logger.error("This is an error message")
