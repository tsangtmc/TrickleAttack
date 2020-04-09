'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

'''
python 3 is http.client
python 2 is httplib
'''
import http.client
import pprint
import json
import ssl

class Create(object):
    '''
    classdocs
    '''

    '''
    # to ignore ssl errors
    conn = http.client.HTTPSConnection(
        HOSTNAME,
        context = ssl._create_unverified_context()
    )
    '''
    def __private_create_connection(self, use_proxy_boolean, use_ssl_boolean, validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer):
        try:
            '''
            (host, port=None, 
            key_file=None, 
            cert_file=None, 
            [timeout, ]
            source_address=None,    #optional source_address parameter may be a tuple of a (host, port) to use as the source address the HTTP connection is made from
             *, 
             context=None            #If context is specified, it must be a ssl.SSLContext instance describing the various SSL options.
             check_hostname=None    #Whether to match the peer cert’s hostname with match_hostname() in SSLSocket.do_handshake(). 
             blocksize=8192            #Buffer size in bytes for sending a file-like message body.
            
            to proxy
            >>> conn = http.client.HTTPSConnection("localhost", 8080)
            >>> conn.set_tunnel("www.python.org"
            '''
            s_address=None # source_address
            #s_address=("www.google.com",443) #just testing when its hard coded
            proxy_final_hostname = hostname
            proxy_final_port = port_integer
            
            if(use_proxy_boolean):
                hostname = "localhost"
                # hardcoding proxy port to 8080 for now
                port_integer = 8080
                
            if(use_ssl_boolean):
                #connection = http.client.HTTPConnection('www.python.org', 80, timeout=10)
                if(validate_sslcert_boolean):
                    conn = http.client.HTTPSConnection(
                    hostname,
                    port=port_integer,
                    source_address = s_address,
                    check_hostname = True,
                    timeout=timeout_seconds_integer
                    )
                    if(use_proxy_boolean):
                        conn.set_tunnel(proxy_final_hostname,proxy_final_port)
                    return conn
                else:
                    conn = http.client.HTTPSConnection(
                    hostname,
                    port=port_integer,
                    timeout=timeout_seconds_integer,
                    source_address = s_address,
                    check_hostname = False,
                    context = ssl._create_unverified_context()
                    )
                    if(use_proxy_boolean):
                        conn.set_tunnel(proxy_final_hostname,proxy_final_port)
                    return conn
                    
            else:
                conn = http.client.HTTPConnection(
                hostname,
                port=port_integer,
                source_address = s_address,
                timeout=timeout_seconds_integer,
                )
                if(use_proxy_boolean):
                        conn.set_tunnel(proxy_final_hostname,proxy_final_port)
                return conn
        except Exception as e:
            print("error")
            print(e)
         
    def Request_GET(self, use_proxy_boolean, use_ssl_boolean, validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer, urlpath, headers_keypairs):
        response = ""
        try:
            #connection = http.client.HTTPConnection('www.python.org', 80, timeout=10)
            print("Creating Connection")
            conn = Create.__private_create_connection(self,use_proxy_boolean,use_ssl_boolean,validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer)
            print("Sending Request")
            '''
            url – URL for the new Request object.
            params – (optional) Dictionary of GET Parameters to send with the Request.
            headers – (optional) Dictionary of HTTP Headers to send with the Request.
            cookies – (optional) CookieJar object to send with the Request.
            auth – (optional) AuthObject to enable Basic HTTP Auth.
            timeout – (optional) Float describing the timeout of the request.
            '''
            conn.request("GET", urlpath, "" , headers = headers_keypairs)
            print("Getting Response")
            response = conn.getresponse()
            print("Status: {} and reason: {}".format(response.status, response.reason))
            
            #Get Headers
            Create.Return_Headers(self, response)
            #Close Connection
            conn.close()
        except Exception as e:
            print("error")
            print(e)
    
        return response
    
    def Request_POST(self, use_proxy_boolean, use_ssl_boolean, validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer, urlpath, body_string, headers_keypairs):
        response = ""
        try:
            conn = Create.__private_create_connection(self,use_proxy_boolean,use_ssl_boolean,validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer)
            conn.request('POST', '/post', body_string, headers_keypairs)
            
            response = conn.getresponse()
            print(response.read().decode())
        except Exception as e:
            print("error")
            print(e)
    
    def Request_Generic(self, http_verb):
        response = ""
        try:
            conn = http.client.HTTPSConnection('www.httpbin.org')

            headers = {'Content-type': 'application/json'}
            
            foo = {'text': 'Hello HTTP #1 **cool**, and #1!'}
            json_data = json.dumps(foo)
            
            conn.request(http_verb, '/'+(http_verb.lower()), json_data, headers)
            
            response = conn.getresponse()
            print(response.read().decode())
        except Exception as e:
            print("error")
            print(e)
    
    def Return_Headers(self, response):
        headers = response.getheaders()
        for header in headers:
            print(header)
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint("Headers: {}".format(headers))
        