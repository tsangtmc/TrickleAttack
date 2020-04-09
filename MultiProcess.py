'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
import _thread
import time
from multiprocessing import Process
import os
'''
This works, but there is alot of memory and cpu overhead. While it provides nice manageability.. its not efficent enough for attacking purposess
'''
def info(title):
    print(title)
    print('module name:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())

def f(name):
    info('function f')
    print('hello', name)
    
def print_time(threadName, delay):
    count = 0
    while count < 5:
        time.sleep(delay)
        count += 1
        print ( threadName + ' [' +str(10-count)+' left]'+time.ctime(time.time()) )
            
def create_treads(threadName, delay):
    try:
        _thread.start_new_thread( print_time, (threadName + ' thread_1 ', delay, ) )
        _thread.start_new_thread( print_time, (threadName + ' thread_2 ', delay, ) )
    except:
        print("Error: unable to start thread")
 
def Multiprocess_something(function, arguments):
    info('main line')
    count = 0
    while count < 10000:
        variable_string = 'Process '+ str(count);
        p = Process(target=function, args=arguments)
        p.start()
        #p.join()
        count += 1
      
if __name__ == '__main__':
    info('main line')
    count = 0
    while count < 10:
        variable_string = 'Process '+ str(count);
        p = Process(target=create_treads, args=(variable_string,1))
        p.start()
        #p.join()
        count += 1
        
