#!/usr/bin/env python

# This file is part of python-libmilter.
# 
# python-libmilter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# python-libmilter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with python-libmilter.  If not, see <http://www.gnu.org/licenses/>.

#
# This is a basic milter for testing
#

import libmilter as lm
import sys , time , re , requests , gevent
import simplejson as json
import logging
import logging.handlers
from gevent import monkey
monkey.patch_socket()
#
# We are going to use an example of a forking version of our milter.  This is
# something not even possible with a regular libmilter implementation
#

# Create our milter class with the forking mixin and the regular milter
# protocol base classes
class ZeroFoxMilter(lm.ForkMixin , lm.MilterProtocol):
    def __init__(self , opts=0 , protos=0):
        # We must init our parents here
        lm.MilterProtocol.__init__(self , opts , protos)
        lm.ForkMixin.__init__(self)
        # You can initialize more stuff here
        self.msgQueue = {}
        self.apiLink = "http://api.riskive.com/v2/link"
        self.apiLinkCheck = "http://api.riskive.com/v2/linkcheck/"
        self.footer = '''____________________________________________________________________
        This email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com
 _____________________________________________________________________'''
        self.foundheader = '''************************************************************************************************
   USE CAUTION: The ZeroFOX Protection Cloud has identified potentially dangerous content within this email. Please take caution when clicking on links and downloading attachments. 
************************************************************************************************\n'''
        self.headers = {"Content-Type": "application/json", "APP_ID":"a02e87e3", "APP_KEY":"1980ed2a6da188b46702ec0971b9fee6"}
        self.timeout = 60
        self.threshold = 60
        self.logger = logging.getLogger("ZF-Milter")
        handler = logging.handlers.SysLogHandle(address = '/var/log/zflog')
        self.logger.addHandler(handler)
    def log(self , msg):
        t = time.strftime('%H:%M:%S')
        print '[%s] %s' % (t , msg)
        sys.stdout.flush()

    # need capability to specify mailFrom and rcptTo for logging via the cmdDict id
    def push(self, id, msg):
        if id in self.msgQueue:
            self.msgQueue[id].append(msg)
        else:
            self.msgQueue[id] = msg

    def get(self, id):
        if id in self.msgQueue:
            return self.msgQueue[id]
        else:
            return None

    def remove(self, id):
        if id in self.msgQueue:
            del self.msgQueue[id]

    @lm.noReply
    def connect(self , hostname , family , ip , port , cmdDict):
        self.log('Connect from %s:%d (%s) with family: %s' % (ip , port ,
            hostname , family))
        return lm.CONTINUE

    @lm.noReply
    def helo(self , heloname):
        self.log('HELO: %s' % heloname)
        return lm.CONTINUE

    @lm.noReply
    def mailFrom(self , frAddr , cmdDict):
        self.log('MAIL: %s' % frAddr)
        return lm.CONTINUE

    @lm.noReply
    def rcpt(self , recip , cmdDict):
        self.log('RCPT: %s' % recip)
        return lm.CONTINUE

    @lm.noReply
    def header(self , key , val , cmdDict):
        self.log('%s: %s' % (key , val))
        return lm.CONTINUE

    @lm.noReply
    def eoh(self , cmdDict):
        self.log('EOH')
        return lm.CONTINUE

    def data(self , cmdDict):
        self.log('DATA')
        return lm.CONTINUE

    @lm.noReply
    def body(self , chunk , cmdDict):
        self.log('begin body')
        self.push(cmdDict['i'], chunk)
        self.log('end body')
        return lm.CONTINUE

    def eob(self , cmdDict):
        self.log('EOB')
        # do we have the body in the queue?
        body = self.get(cmdDict['i'])
        badlink = False
        if body is not None:
            # check body for links
            links = self.getLinks(body)
            # if the array of links > 0, we have links to check
            if len(links) != 0:
                # append http:// to links that dont have it
                links = set(["http://" + s if not s.startswith("http") else s for s in links])
                # insert each link into the link api for an id
                # we will later check each id for threshold
                insertLinkJobs = [gevent.spawn(self.insertLink, link) for link in links]
                gevent.joinall(insertLinkJobs, timeout=15)
                #filter out Nones in case for failed api requests
                insertLinkJobs = filter(None, [job for job in insertLinkJobs])
                if len(insertLinkJobs) != 0:
                    linkEndPoints = dict([job.value for job in insertLinkJobs])
                    self.log('Links to check: %s ' % str(linkEndPoints))
                    # spawn threadpool to asynchronously poll API for a total of one minute to get results
                    checkLinkJobs = [gevent.spawn(self.checkLink, url, id) for url,id in linkEndPoints.items()]
                    gevent.joinall(checkLinkJobs, timeout=60)
                    # gevent will return None to the list, so filter those out
                    checkLinkJobs = filter(None,[job.value for job in checkLinkJobs])
                    if len(checkLinkJobs) != 0:
                        highest = max([job[1] for job in checkLinkJobs])
                        self.log('Highest score: %s' % str(highest))
                        if highest > self.threshold:
                            badlink = True
                            url = [item for item in checkLinkJobs if item[1] == highest]
                            self.log('Bad link present!')
                            self.logger.warning(json.dumps({"msg":"Bad url present", "url":url, "score":str(highest)}))
            if badlink:
                self.replBody(self.foundheader + ' ' + body + ' ' + self.footer)
            else:            
                self.replBody(body + ' ' + self.footer)
            self.remove(cmdDict['i'])
        return lm.CONTINUE

    # inserts a single link and returns its id
    def insertLink(self, url):
        self.log('Inserting %s ' % url)
        apiLinkPayload = {"link": {"uri": url, "threshold": 60}}
        r = requests.post(self.apiLink, data=json.dumps(apiLinkPayload), headers=self.headers)
        resp = r.json()
        if 'error_message' in resp:
            return None
        else:
            return (url,resp['request_id'])
    def close(self):
        self.log('Close called. QID: %s' % self._qid)

    def getLinks(self, body):
       return set(re.findall('((?:http://|https://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z\-]+(?:/[a-zA-Z0-9_\-\%/\.#!\?&\+=]+)?)', body))

    def checkLink(self, url, id):
       self.log('Checking URL %s ' % url)
       default = 0 
       maxRetries = 0
       endpt = self.apiLinkCheck + id
       lcv = True
       while lcv:
           r = requests.get(endpt, headers=self.headers)
           r_json = r.json()
           if r_json['done']:
               self.log('Link done!')
               self.log('Json: %s' % str(r_json))
               return (url, r_json['response']['info']['score'])
           else:
               maxRetries += 1
               if maxRetries == self.timeout:
                   lcv = False
               else:
                   gevent.sleep(1)
       return (url,default)

def runZeroFoxMilter():
    import signal , traceback
    # We can set our milter opts here
    opts = lm.SMFIF_CHGFROM | lm.SMFIF_ADDRCPT | lm.SMFIF_QUARANTINE | lm.SMFIF_CHGBODY

    # We initialize the factory we want to use (you can choose from an 
    # AsyncFactory, ForkFactory or ThreadFactory.  You must use the
    # appropriate mixin classes for your milter for Thread and Fork)
    f = lm.ForkFactory('inet:127.0.0.1:5000' , ZeroFoxMilter , opts)
    def sigHandler(num , frame):
        f.close()
        sys.exit(0)
    signal.signal(signal.SIGINT , sigHandler)
    try:
        # run it
        f.run()
    except Exception , e:
        f.close()
        print >> sys.stderr , 'EXCEPTION OCCURED: %s' % e
        traceback.print_tb(sys.exc_traceback)
        sys.exit(3)

if __name__ == '__main__':
    runZeroFoxMilter()
