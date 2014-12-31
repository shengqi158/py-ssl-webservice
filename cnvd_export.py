import urllib2, httplib, socket
from suds.client import Client
from suds.transport.http import HttpTransport, Reply, TransportError
import ssl

class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert, passwd):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert
        self.passwd = passwd
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.ssl_context.load_cert_chain(cert, key, passwd)


    def https_open(self, req):
        #Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        #return self.do_open(self.getConnection, req)
        return self.do_open(self.get_connection, req)

    def get_connection(self, host, timeout=300):
        return httplib.HTTPSConnection(host,timeout=timeout,context=self.ssl_context)

class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, key, cert, passwd, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert
        self.passwd = passwd

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        url = urllib2.build_opener(HTTPSClientAuthHandler(self.key, self.cert, self.passwd))
        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)

def get_client(wsdl_url, key, cert, passwd):

    # These lines enable debug logging; remove them once everything works.
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('suds.client').setLevel(logging.DEBUG)
    logging.getLogger('suds.transport').setLevel(logging.DEBUG)
    transport = HTTPSClientCertTransport(key, cert, passwd)
    c = Client(wsdl_url, transport = transport)
    return c

def open_ssl(key, cert):
    from OpenSSL import SSL
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_passwd_cb(lambda *unused: "yourpassword")
    ctx.use_privatekey_file(key)
    ctx.use_certificate_file(cert)
    mysocket = SSL.Connection(ctx, socket.socket())
    return mysocket


if __name__ == "__main__":
    wsdl_url = "https://www.cnvd.org.cn:8443/cnvd/services/flawInfo?wsdl"
    key = ""
    cert = ""
    passwd = ""
    client = get_client(wsdl_url, key, cert)
    version = client.invoke(["2013-08-01","2013-08-17"])
    print version
