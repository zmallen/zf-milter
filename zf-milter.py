## To roll your own milter, create a class that extends Milter.  
#  See the pymilter project at http://bmsi.com/python/milter.html
#  based on Sendmail's milter API http://www.milter.org/milter_api/api.html
#  This code is open-source on the same terms as Python.

## Milter calls methods of your class at milter events.
## Return REJECT,TEMPFAIL,ACCEPT to short circuit processing for a message.
## You can also add/del recipients, replacebody, add/del headers, etc.

import Milter, re, StringIO, time, email, sys, gevent, requests, logging, rfc822, mime, tempfile, syslog, signal, time
from threading import Thread
from socket import AF_INET, AF_INET6
import simplejson as json
from gevent import monkey
monkey.patch_socket()
syslog.openlog(facility=syslog.LOG_MAIL)
from Milter.utils import parse_addr

class zfMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.
    self.apiLink = "http://api.riskive.com/v2/link"
    self.apiLinkCheck = "http://api.riskive.com/v2/linkcheck/"
    self.line = "_" * 64
    self.ast = "*" * 64
    self.footer = '''\n\n
\n\nThis email was scanned by the ZeroFOX Protection Cloud security service.\nFor more information please visit http://www.ZeroFOX.com
    \n\n'''
    self.footer_html = '''<br><hr>This email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com<br><hr>'''
    self.footer_regex = r'''(____________________________________________________________________\nThis email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com)|(<hr><br>This email was scanned by the ZeroFOX Protection Cloud security service. For more information please visit http://www.ZeroFOX.com<br><hr>)'''
    self.foundheader_html = '''<br>%s<br>USE CAUTION: The ZeroFOX Protection Cloud has identified potentially dangerous content within this e-mail.<br>%s<br>''' % (self.ast, self.ast)
    self.foundheader = '''\n%s\nUSE CAUTION: The ZeroFOX Protection Cloud has identified potentially dangerous content within this email. Please take caution when clicking on links and downloading attachments.\n%s\n''' % (self.ast, self.ast)
    self.headers = {"Content-Type":"application/json", "APP_ID":"a02e87e3", "APP_KEY":"1980ed2a6da188b46702ec0971b9fee6"}
    self.mail_headers = {}
    self.sleeptime = 5
    self.link_timeo = 60
    self.threshold = 60
    self.linkscoremap = {}

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
    
    return Milter.CONTINUE


  ##  def hello(self,hostname):
  def hello(self, heloname):
    self.H = heloname
    if heloname.find('.') < 0:  # illegal helo name
      self.setreply('550','5.7.1','Sheesh people!  Use a proper helo name!')
      return Milter.REJECT
      
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    self.F = mailfrom
    self.R = []  # list of recipients
    self.fromparms = Milter.dictfromlist(str)   # ESMTP parms
    self.user = self.getsymval('{auth_authen}') # authenticated user
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

  def setmultifooters(self, msg):
    links = set()
    plainVisit = False
    htmlVisit = False
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if not plainVisit and part.get_content_subtype() == 'plain':
             plainVisit = True
             email_charset = part.get_charset()
             payload = part.get_payload(decode=True)
             links2 = self.getlinks(payload)
             links = links.union(links2)
             new_pay = payload + self.footer
             part.set_payload(new_pay, email_charset)
        if not htmlVisit and part.get_content_subtype() == 'html':
            htmlVisit = True
            email_charset = part.get_charset()
            html = part.get_payload(decode=True)
            links2 = self.getlinks(html)
            links = links.union(self.getlinks(html))
            if '</body>' in html:
                html = html.replace("""</body>""", """%s</body>""" % self.footer_html)
                part.set_payload(html, email_charset)
            else:
                new_pay = html + self.footer_html
                part.set_payload(new_pay, email_charset) 
        if plainVisit and htmlVisit:
            break
    return msg, links   

  def setmultiheader(self, msg):
    plainVisit = False
    htmlVisit = False
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if not plainVisit and part.get_content_subtype() == 'plain':
            plainVisit = True
            payload = part.get_payload()
            new_pay = self.foundheader + payload
        if not htmlVisit and part.get_content_subtype() == 'html':
            htmlVisit = True
            html = part.get_payload()
            if '<body>' in html:
                html = html.replace("""<body>""", """<body>%s""" % self.foundheader_html)
                part.set_payload(html)
            else:
                payload = part.get_payload()
                new_pay = self.foundheader_html + payload
                part.set_payload(new_pay)
        if plainVisit and htmlVisit:
            break
    return msg

  def logemail(self, msg):
    fromHeader = str(msg.getheaders('from'))
    toHeader = str(msg.getheaders('to'))
    syslog.syslog(syslog.LOG_INFO, json.dumps({"id":"id:%s MAIL" % str(1006), "msg":"email", "to":toHeader, "from":fromHeader}))

  def eom(self):
    try:
        self.fp.seek(0)
        msg = mime.message_from_file(self.fp)
        self.logemail(msg)
        links = set()
        if (msg.ismultipart()):
            msg, links = self.setmultifooters(msg)
        else:
            email_charset = msg.get_charset()
            payloadout = msg.get_payload() + self.footer
            links = self.getlinks(msg.get_payload())
            msg.set_payload(payloadout, email_charset)
        if len(links) > 0:
            badlink = False
            # append http:// to links that do not have it
            links = list(set(["http://" + s if not s.startswith("http") else s for s in links]))
            # insert each link into the link api for an id
            # we will later check each id for theeshold
            threads = [None] * len(links)
            for i in range(len(threads)):
                threads[i] = Thread(target=self.insertLink, args=(links[i],))
                threads[i].start()
            for i in range(len(threads)):
                threads[i].join()
            # filter out Nones in case for failed api eequests
            # gevent will return None to the list if it didnt get an answer, so filter those out
            # got some scores!
            highest = max([urlTup[1] for urlTup in self.linkscoremap.values()])
            if highest > self.threshold:
                badlink = True
                url = [urlTup[0] for urlTup in self.linkscoremap.values() if urlTup[1] == highest]
                syslog.syslog(syslog.LOG_WARNING, (json.dumps({"id":"id:%s BADURLPRESENT" % str(2003), "msg":"BADURLPRESENT", "url":str(url), "score":str(highest), "time":time.strftime('%y%b%d %H:%M:%S'), "to":str(msg.getheaders('to')), "from":str(msg.getheaders('from'))})))
            if badlink:
                if msg.ismultipart():
                    msg = self.setmultiheader(msg)
                else:
                    payloadout = self.foundheader + msg.get_payload()
                    msg.set_payload(payloadout)
        out = tempfile.TemporaryFile()  
        msg.dump(out)
        out.seek(0)
        msg = rfc822.Message(out)
        msg.rewindbody()
        while 1:
            buf = out.read(8192)
            if len(buf) == 0: break
            self.replacebody(buf)
    except Exception, e:
        syslog.syslog(syslog.LOG_WARNING, (json.dumps({id:"id:%s ERRORMILTER" % str(2006), "msg":str(e)}))) 
    finally:
        out.close()
    return Milter.ACCEPT

  def insertLink(self, url):
    try:
        apiLinkPayload = {"link": {"uri": url, "threshold": 60, "enterprise":"ZeroFoxEmail"}}
        r = requests.post(self.apiLink, data=json.dumps(apiLinkPayload), headers=self.headers)
        resp = r.json()
        if 'error_message' in resp:
            return
        else:
            self.linkscoremap[resp['request_id']] = [url, 0]
            self.checklink(resp['request_id'], url)
    except:
        return

  # parse email content with python email parser
  def getlinks(self, body):
     return set(re.findall('((?:http://|https://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z\-]+(?:/[a-zA-Z0-9_\-\%/\.#!\?&\+=]+)?)', body))

  def checklink(self, id, url):
     maxRetries = 0
     endpt = self.apiLinkCheck + id
     lcv = True
     while lcv:
         r = requests.get(endpt, headers=self.headers)
         r_json = r.json()
         if r_json.has_key('error_code'):
             return
         elif r_json.has_key('done'):
             if r_json['done']:
                score = r_json['response']['info']['score']
                self.linkscoremap[id] = [url,r_json['response']['info']['score']]
                return
                #return (r_json['response']['info']['url'],r_json['response']['info']['score'])
         maxRetries += self.sleeptime
         if maxRetries >= self.link_timeo:
             lcv = False
         else:
             time.sleep(self.sleeptime)
     return

  def close(self):
    # always called, even when abort is called.  Clean up
    # any external resources here.
    return Milter.CONTINUE

  def abort(self):
    # client disconnected prematurely
    return Milter.CONTINUE
## ===
    
def main():
  socketname = "/var/spool/postfix/var/run/zf/sock"
  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = zfMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  flags += Milter.ADDRCPT
  flags += Milter.DELRCPT
  Milter.set_flags(flags)       # tell Sendmail which features we use
  syslog.syslog(syslog.LOG_INFO, json.dumps({"id":"id:%s MILTERSTART" % str(1005), "msg":"%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')}))
  sys.stdout.flush()
  Milter.runmilter("zfmilter",socketname,timeout)
  print "%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()
