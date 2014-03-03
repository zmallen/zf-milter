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
Point a unix socket location from within main.cf under smtpd_milters

Postfix runs chroot'ed under /var/spool/postfix, so a test can be made at:
/var/run/zf/sock, making the fully qualified path: 
/var/spool/postfix/var/run/zf/sock

The config option would then be:
smtpd_milters = unix:/var/run/zf/sock

chown all of the directories holding it

Run the milter as the postfix user:
su postfix -c "python zf.milter.py"

tail -f /var/log/mail for any relevant output info

Todo:

Redis integration of URL -> Score to minimize API look ups
