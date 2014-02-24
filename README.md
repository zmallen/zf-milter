zf-milter
=========

Use this as a plugin to postfix servers to scan for links, submit all of them to our API and check bad thresholds

To get an API key, send a request to:
getapi@zerofox.com

Needs:
========
libmilter-dev
pymilter, re, json, requests, postfix

To run:
=======
Run the milter as the zf-milter user
Make sure you create a socket location in linux under
/var/spool/postfix
and update it in the script under "socketname"

Postfix must own all of these directories, so chown /var/spool/postfix/var/run/zf/sock

Under the configuration file, main.cf, set
smtpd_milters =
to
smtpd_milters = unix:/var/run/zf/sock 
Postfix runs under chroot under /var/spool/postfix, so you dont need that.


Todo:

Redis integration of URL -> Score to minimize API look ups