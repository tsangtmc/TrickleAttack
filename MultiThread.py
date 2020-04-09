'''
@author: Jason Tsang Mui Chung

License Copyright: MIT
Copyright 2020 Jason Tsang Mui Chung

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
from threading import Thread

#concurrent = 20000

'''
def functiondoWork(function, arguments):
    while True:
        url = q.get()
        status, url = getStatus(url)
        doSomethingWithResult(status, url)
        q.task_done()

def getStatus(conn):
    try:
        conn = http.client.HTTPConnection(url.netloc)   
        conn.request("HEAD", url.path)
        res = conn.getresponse()
        return res.status
    except:
        return "error"

def doSomethingWithResult(status, url):
    print(status +"   " + url)
'''

def Multithread_something(function, arguments, threadcount, thread_list):
    #q = queue.Queue(concurrent * 2)          
    for i in range(threadcount):
        t = Thread(target=function, args=arguments)
        t.daemon = True
        thread_list.append(t)
        t.start()
        #print("started "+str(i))
