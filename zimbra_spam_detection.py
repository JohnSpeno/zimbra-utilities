#!/usr/local/bin/python
"""
Scans Zimbra and Postfix maillogs to determine how much mail each sender has
sent (via ZWC only) and warns if too much mail was sent by someone.

Also warns about mail sent from outside addresses.

Can automatically lock Zimbra accounts if more than --critical option messages
were sent by an account.

Accounts in a whitelist file are exempt from warning and locking.
"""
import time
import re
from optparse import OptionParser

MY_DOMAIN = 'yourdomain.com'
MY_HOSTNAME = 'myhostname.yourdomain.com'

getmessageid = re.compile(r'\[name=([^@]+)@.*Message-ID=<([^>]+)>').search

getpostfixmessageid = re.compile(
    "postfix\/cleanup.*message-id=<([^>]+)>").search

class EmailBurst(object):
    def __init__(self, logfilename='/var/log/syslog/mail.log',
                    mailboxlog='/opt/zimbra/log/mailbox.log',
                    whitelist=None):
        """
        mailboxlog - The zimbra log.
        logfilename - The postfix log.
        whitelist - list of exempt sender addresses.
        """
        self.logfilename = logfilename
        self.mailboxlogfilename = mailboxlog
        self.logfile = None
        self.mailboxlog = None
        if whitelist is None:
            whitelist = []
        self.whitelist = whitelist
        self.queueids = {}

    def tailfile(self):
        self.logfile.seek(0, 2)
        self.mailboxfile.seek(0, 2)

    def openfile(self):
        self.logfile = open(self.logfilename)
        self.mailboxfile = open(self.mailboxlogfilename)        

    def getrate(self):
        total_sent = 0
        senderdict = {}
        outsiders = {}
        realsenders = {}

        # first retrieve "real" sender ID from mailbox.log
        for l in self.mailboxfile:
            m = getmessageid(l)
            if m:
                (sender, messageid) = m.groups()
                realsenders[messageid] = sender

        # now examine mail log for webmail entries
        client = 'client=%s' % MY_HOSTNAME
        for l in self.logfile:
            if "postfix/smtpd" in l and client in l:
                parts = l.split()
                try:
                    queueid = parts[5]
                except IndexError:
                    continue
                self.queueids[queueid] = True
            elif "postfix/cleanup" in l:
                parts = l.split()
                try:
                    queueid = parts[5]
                except IndexError:
                    continue
                if queueid in self.queueids:
                    # find real sender
                    messageid = parts[6][12:-1]
                    self.queueids[queueid] = realsenders.get(messageid, 'Unknown')
            elif "postfix/qmgr" in l and "from=" in l:
                try:
                    parts = l.split()
                    queueid = parts[5]
                    if queueid not in self.queueids:
                        continue
                    recipients = int(parts[-3].split('=')[-1])
                    fromaddr =  parts[6][6:-2]
                    realsender = self.queueids.get(queueid)                    
                    if not fromaddr:
                        fromaddr = 'mailer-daemon'
                    keyid = (fromaddr, realsender)
                    fl = fromaddr.lower()
                    if (
                        fromaddr != 'mailer-daemon'
                        and not fl.endswith(MY_DOMAIN)
                        and fl not in self.whitelist
                    ):
                        sendercnt = outsiders.get(fromaddr, 0)
                        sendercnt += recipients
                        if realsender != 'Unknown':
                            outsiders[keyid] = sendercnt

                    sendercnt = senderdict.get(keyid, 0)
                    sendercnt += recipients
                    # individual count
                    if realsender != 'Unknown':
                        senderdict[keyid] = sendercnt
                        # total count
                        total_sent += recipients
                except:
                    total_sent += 1
        senderlist = list(senderdict.iteritems())

        return total_sent, senderlist, outsiders

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option('--maillog',dest="maillog", help="postfix maillog")
    parser.add_option('--mailboxlog',dest="mailboxlog",
                     help="zimbra mailboxlog"
    )
    parser.add_option('--quiet', '-q', dest="quiet",
                      help="supress report output",
                      default=False, action="store_true"
    )
    parser.add_option('--warn', dest="warn",
                      help="messages per minute (default warn 100 msgs/minute)",
                      default=100, type='int'
    )
    parser.add_option('--critical', dest="critical",
                      help="messages per minute (lock after 1000 msgs/minute)",
                      default=1000, type='int'
    )    
    parser.add_option('--timeinterval', dest="timeinterval",
                      help="monitor for X minutes (default 5)",
                      default=5, type='int'
    )
    parser.add_option('-t','--test', dest='test',
                      help="test mode", action='store_true', default=False
    )

    options, args = parser.parse_args()
   
    try:
        whitelist = open('/usr/local/etc/badspammer/whitelist.txt').read()
        whitelist = whitelist.lower().split('\n')
    except:
        whitelist = None
    
    e = EmailBurst(whitelist=whitelist)
    if options.maillog:
        e.logfilename = options.maillog
    if options.mailboxlog:
        e.mailboxlogfilename = options.mailboxlog
        
    e.openfile()

    if options.timeinterval:
        e.tailfile()
        time.sleep(options.timeinterval * 60)

    total_msgs_sent, senderlist, outsiders = e.getrate()

    if options.timeinterval:
        msgs_per_minute =  total_msgs_sent / options.timeinterval
    else:
        msgs_per_minute = total_msgs_sent / 5

    # sort the list based on messages sent
    senderlist.sort(lambda a, b: cmp(b[1], a[1]))

    if outsiders and not options.quiet:
        print "Automated Warning: Alert non-upenn.edu message sent\n"
        for sender in outsiders:            
            print "%d:\t%s (%s)" %(outsiders[sender], sender[0], sender[1])
            
    if msgs_per_minute > options.warn and not options.quiet:
        print (
            "Automated Warning: Alert %d messages sent by webmail "
            "in one minute\n" % (options.warn)
        )
        print "Top senders"
        for (sender, msgs) in senderlist[:5]:
            print "%d:\t%s (%s)" % (msgs, sender[0], sender[1])
            
    for sender, msgs_sent in senderlist:
        if options.timeinterval:
            msgs_per_minute =  msgs_sent / options.timeinterval
        else:
            msgs_per_minute = msgs_sent / 5
            
        if msgs_per_minute > options.critical:
            print "LOCKING %s %d messages sent/minute" % (
                sender[1], msgs_per_minute
            )
            # do account lock here
