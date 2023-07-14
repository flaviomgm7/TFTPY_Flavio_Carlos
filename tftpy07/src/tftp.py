"""
This module handles all TFTP related "stuff": data structures, packet 
definitions, methods and protocol operations.

(C) João Galamba, 2023
"""


###############################################################
##
##      ERRORS AND EXCEPTIONS
##
###############################################################

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """

