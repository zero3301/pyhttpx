

_tls_kx_algs = {}

class EncryptedPreMasterSecret:
    pass
class _GenericKXMetaclass(type):

    def __new__(cls, kx_name, bases, dct):
        if kx_name != "_GenericKX":
            dct["name"] = kx_name[3:]       # remove leading "KX_"
        the_class = super(_GenericKXMetaclass, cls).__new__(cls, kx_name,
                                                            bases, dct)
        if kx_name != "_GenericKX":
            the_class.export = kx_name.endswith("_EXPORT")
            the_class.anonymous = "_anon" in kx_name
            the_class.no_ske = not ("DHE" in kx_name or "_anon" in kx_name)
            the_class.no_ske &= not the_class.export
            _tls_kx_algs[kx_name[3:]] = the_class
        return the_class



class _GenericKX(metaclass=_GenericKXMetaclass):
    pass

class KX_RSA(_GenericKX):
    descr = "RSA encryption"
    server_kx_msg_cls = lambda _, m: None
    client_kx_msg_cls = EncryptedPreMasterSecret