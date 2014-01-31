## To roll your own milter, create a class that extends Milter.  
#  See the pymilter project at http://bmsi.com/python/milter.html
#  based on Sendmail's milter API http://www.milter.org/milter_api/api.html
#  This code is open-source on the same terms as Python.

## Milter calls methods of your class at milter events.
## Return REJECT,TEMPFAIL,ACCEPT to short circuit processing for a message.
## You can also add/del recipients, replacebody, add/del headers, etc.

import Milter, re, StringIO, time, email, sys, gevent, requests, logging, rfc822, mime, tempfile
from socket import AF_INET, AF_INET6
import simplejson as json
from gevent import monkey
monkey.patch_socket()
from Milter.utils import parse_addr
if True:
  from multiprocessing import Process as Thread, Queue
else:
  from threading import Thread
  from Queue import Queue

logq = Queue(maxsize=4)

class zfMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.
    self.apiLink = "http://api.riskive.com/v2/link"
    self.apiLinkCheck = "http://api.riskive.com/v2/linkcheck/"
    self.footer = '''____________________________________________________________________\nThis email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com
'''
    self.footer_html = '''<hr><br>This email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com<br><hr>'''
    self.foundheader = '''************************************************************************************************
       USE CAUTION: The ZeroFOX Protection Cloud has identified potentially dangerous content within this email. Please take caution when clicking on links and downloading attachments.
       ************************************************************************************************\n'''
    self.headers = {"Content-Type":"application/json", "APP_ID":"a02e87e3", "APP_KEY":"1980ed2a6da188b46702ec0971b9fee6"}
    self.mail_headers = {}
    self.timeout = 60
    self.threshold = 60

  # each connection runs in its own thread and has its own zfMilter
  # instance.  Python code must be thread safe.  This is trivial if only stuff
  # in zfMilter instances is referenced.
  @Milter.noreply
  def connect(self, IPname, family, hostaddr):
    self.IP = hostaddr[0]
    self.port = hostaddr[1]
    if family == AF_INET6:
      self.flow = hostaddr[2]
      self.scope = hostaddr[3]
    else:
      self.flow = None
      self.scope = None
    self.IPname = IPname  # Name from a reverse IP lookup
    self.H = None
    self.fp = None
    self.receiver = self.getsymval('j')
    #self.log("connect from %s at %s" % (IPname, hostaddr) )
    
    return Milter.CONTINUE


  ##  def hello(self,hostname):
  def hello(self, heloname):
    self.H = heloname
    #self.log("HELO %s" % heloname)
    if heloname.find('.') < 0:  # illegal helo name
      self.setreply('550','5.7.1','Sheesh people!  Use a proper helo name!')
      return Milter.REJECT
      
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    self.F = mailfrom
    self.R = []  # list of recipients
    self.fromparms = Milter.dictfromlist(str)   # ESMTP parms
    self.user = self.getsymval('{auth_authen}') # authenticated user
    #self.log("mail from:", mailfrom, *str)
    self.fp = StringIO.StringIO()
    self.canon_from = '@'.join(parse_addr(mailfrom))
    #self.fp.write('From %s %s\n' % (self.canon_from,time.ctime()))
    return Milter.CONTINUE


  ##  def envrcpt(self, to, *str):
  @Milter.noreply
  def envrcpt(self, to, *str):
    rcptinfo = to,Milter.dictfromlist(str)
    self.R.append(rcptinfo)
    return Milter.CONTINUE

  @Milter.noreply
  def header(self, name, hval):
    self.fp.write("%s: %s\n" % (name,hval))     # add header to buffer
    return Milter.CONTINUE

  @Milter.noreply
  def eoh(self):
    self.fp.write("\n")                         # terminate headers
    return Milter.CONTINUE

  @Milter.noreply
  def body(self, chunk):
    self.fp.write(chunk)
    return Milter.CONTINUE

  def getbody(self, msg):
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get_content_subtype() == 'plain':
            payload = part.get_payload()
            part.set_payload(payload + '\n' + self.footer)
        if part.get_content_subtype() == 'html':
            html = part.get_payload()
            if '</body>' in html:
                html = html.replace("""</body>""", """%s</body>""" % self.footer_html)
                part.set_payload(html)
            else:
                payload = part.get_payload()
                part.set_payload(payload + '\n' + self.footer) 
    return msg   

  def eom(self):
    self.fp.seek(0)
    msg = mime.message_from_file(self.fp)
    if (msg.ismultipart()):
        msg = self.getbody(msg)
    else:
        msg.set_payload(msg.get_payload() + '\n' + self.footer)
    # parse here for urls
    out = tempfile.TemporaryFile()  
    try:
        msg.dump(out)
        out.seek(0)
        msg = rfc822.Message(out)
        msg.rewindbody()
        while 1:
            buf = out.read(8192)
            if len(buf) == 0: break
            self.replacebody(buf)
    except Error as e:
        self.log(str(e))
    finally:
        out.close()
    return Milter.ACCEPT
    # this is for later
    body = self.getbody(msg) + "\n" + self.footer
    # add to end
    # testing
    body = None
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
        insertLinkJobs = filter(None, [job.value for job in insertLinkJobs])
        if len(insertLinkJobs) > 0:
            linkEndPoints = [job['request_id'] for job in insertLinkJobs]
            # spawn threadpool to asynchronously poll API for a total of one minute to get results
            checkLinkJobs = [gevent.spawn(self.checkLink, id) for id in linkEndPoints]
            gevent.joinall(checkLinkJobs, timeout=60)
            # gevent will return None to the list, so filter those out
            checkLinkJobs = filter(None,[job.value for job in checkLinkJobs])
            if len(checkLinkJobs) != 0:
                highest = max([job[1] for job in checkLinkJobs])
                self.log('Highest score: %s' % str(highest))
                if highest > self.threshold:
                    badlink = True
                    url = [item[0] for item in checkLinkJobs if item[1] == highest]
                    self.log(json.dumps({"msg":"Bad url present", "url":url, "score":str(highest)}))
        if badlink:
            self.replacebody(self.foundheader + ' ' + body + ' ' + self.footer)
        else:            
            self.replacebody(body + ' ' + self.footer)
    # many milter functions can only be called from eom()
    # example of adding a Bcc:
    return Milter.ACCEPT

  def insertLink(self, url):
  #      self.log('Inserting %s ' % url)
        apiLinkPayload = {"link": {"uri": url, "threshold": 60}}
        r = requests.post(self.apiLink, data=json.dumps(apiLinkPayload), headers=self.headers)
        resp = r.json()
        if 'error_message' in resp:
            self.log('Error!')
            return None
        else:
            return resp

  # parse email content with python email parser
  def getLinks(self, body):
     return set(re.findall('((?:http://|https://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z\-]+(?:/[a-zA-Z0-9_\-\%/\.#!\?&\+=]+)?)', body))

  def checkLink(self, id):
     default = 0 
     maxRetries = 0
     endpt = self.apiLinkCheck + id
     lcv = True
     while lcv:
         r = requests.get(endpt, headers=self.headers)
         r_json = r.json()
         if r_json['done']:
             return (r_json['response']['info']['url'],r_json['response']['info']['score'])
         else:
             maxRetries += 1
             if maxRetries == self.timeout:
                 lcv = False
             else:
                 gevent.sleep(1)
     return default

  def close(self):
    # always called, even when abort is called.  Clean up
    # any external resources here.
    return Milter.CONTINUE

  def abort(self):
    # client disconnected prematurely
    return Milter.CONTINUE

  ## === Support Functions ===

  def log(self,*msg):
    logq.put((msg,self.id,time.time()))

def background():
  while True:
    t = logq.get()
    if not t: break
    msg,id,ts = t
    print "%s [%d]" % (time.strftime('%Y%b%d %H:%M:%S',time.localtime(ts)),id),
    # 2005Oct13 02:34:11 [1] msg1 msg2 msg3 ...
    for i in msg: print i,
    print

## ===
    
def main():
  bt = Thread(target=background)
  bt.start()
  socketname = "/var/spool/postfix/var/run/zf/sock"
  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = zfMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  flags += Milter.ADDRCPT
  flags += Milter.DELRCPT
  Milter.set_flags(flags)       # tell Sendmail which features we use
  print "%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')
  sys.stdout.flush()
  Milter.runmilter("zfmilter",socketname,timeout)
  logq.put(None)
  bt.join()
  print "%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()
