'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
from threading import Thread
import time
from Concurrent_Requests import Run

def TrickleAttack_to_csv_print_headersinfile(filename):
    try: 
        #(print_queue_list, elapsed_time, status_code, str(http_response_length), http_response, thread_list)
        with open(filename, "a") as myfile:
            myfile.write("time_of_entry, round_trip_time_seconds, status_code, http_response_length_bytes, http_response" + "\n")  
    except Exception as e:
        ab = 0

def TrickleAttack_to_csv_printqueue_MultiThreaded(
        print_queue_list, 
        rtt_string, 
        statuscode_string, 
        reponsesize_string, 
        reponse_string, 
        thread_list
        ):
    new_csv_line = ("\""+str(time.time()) + "\",\""
                    + csv_sanitize(rtt_string) +"\",\""
                    + csv_sanitize(statuscode_string) +"\",\""
                    + csv_sanitize(reponsesize_string) +"\",\""
                    +csv_sanitize(reponse_string)+"\"")
    print_queue_list.append(new_csv_line)
    #print(new_csv_line)
    
def csv_sanitize(input_string):
    return input_string.replace("\"", "\"\"")

def start_printer_csv_MultiThreaded(print_queue_list, filename, thread_list):
    
    t = Thread(target=__private_print_csv_MultiThreaded, args=(print_queue_list, filename, thread_list))
    t.daemon = True
    t.start()   
    '''
    print(len(thread_list))
    while((not Run.All_Threads_Done) or (len(print_queue_list)>0)):
    #while(True):
        print("started printing")
        time.sleep(3) #print every 3 seconds.. just because
        count=10 #do 10 at a time
        while (count > 0):
            try:
                with open(filename, "a") as myfile:
                    if(len(print_queue_list)>0):
                        myfile.write(print_queue_list.pop(0) + "\n")  
            except Exception as e:
                count = count
            count = count - 1
    print("done printing") 
    '''
        
def __private_print_csv_MultiThreaded(print_queue_list, filename, thread_list):
    '''
    print(len(thread_list))
    while(len(thread_list)>0):
        print("started printing")
        time.sleep(3) #print every 3 seconds.. just because
        count=10 #do 10 at a time
        while (count > 0):
            with open(filename, "a") as myfile:
                myfile.write(print_queue_list.pop(0))  
            count = count - 1
    print("done printing")
    '''
    print(len(thread_list))
    print("Started Printing Results")
    status_update_count=0
    
    while((len(thread_list) > 0) or (len(print_queue_list)>0)):
        time.sleep(1) #print every 1 seconds.. just because
        count=1000 #do 1000 at a time, up it to be more aggressive but its all about disk IO
        while (count > 0):
            count = count - 1
            try:
                with open(filename, "a") as myfile:
                    if(len(print_queue_list)>0):
                        myfile.write(print_queue_list.pop(0) + "\n")  
            except Exception as e:
                ab = 0
            
        status_update_count= status_update_count + 1 
        if(status_update_count > 2):#every 3 loops print status, so at 3 seconds of sleep it will print status
            status_update_count= 0 
            print("still printing results... ["+str(len(print_queue_list))+" items To Print][["+str(len(thread_list))+" threads still working]")
            #TrickleAttack_to_csv_printqueue_MultiThreaded(print_queue_list, "test", "test2", "test3", "test4", thread_list)
    print("done printing") 