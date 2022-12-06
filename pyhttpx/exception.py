
class BaseExpetion(Exception):
    pass

class TLSVerifyDataExpetion(BaseExpetion):
    pass

class TLSHandshakeFailed(BaseExpetion):
    pass
class TLSDecryptErrorExpetion(BaseExpetion):
    pass

class TLSEncryptedAlertExpetion(BaseExpetion):
    pass

class TLSCipherNotSupportedErrorExpetion(BaseExpetion):
    pass
class TLSECCNotSupportedErrorExpetion(BaseExpetion):
    pass

class ConnectionAbortedError(BaseExpetion,):
    pass
class ConnectionTimeout(BaseExpetion):
    pass

class ConnectionClosed(BaseExpetion):
    pass

class ReadTimeout(BaseExpetion):
    pass
class TooManyRedirects(BaseExpetion):
    pass


#websocket
class SwitchingProtocolError(BaseExpetion):
    pass
class SecWebSocketKeyError(BaseExpetion):
    pass
class WebSocketClosed(BaseExpetion):
    pass

class ProxyError(IOError):
    """Socket_err contains original socket.error exception."""
    def __init__(self, msg, socket_err=None):
        self.msg = msg
        self.socket_err = socket_err

        if socket_err:
            self.msg += ": {}".format(socket_err)

    def __str__(self):
        return self.msg

