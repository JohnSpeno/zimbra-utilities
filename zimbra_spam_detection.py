#!/usr/local/bin/python
'''
Scans Zimbra and Postfix log files to determine how much mail each sender has
sent.

Warns if too much mail was sent by someone.

Also warns about mail sent from outside addresses.

Can automatically lock Zimbra accounts if more than --lock option messages
were sent by an account.

Accounts in a whitelist file are exempt from warning and locking.
'''
import collections
import time
import re
from operator import itemgetter
from optparse import OptionParser

MY_DOMAIN = 'yourdomain.com'

def lock_account(sender, count):
    '''
    Insert code to lock an account here.
    '''
    pass

# zimbra mailbox log
# groups = (user, message id)
get_mid2user = re.compile(
    r'\[name=([^@;]+).* smtp .*Message-ID=<([^>]+)>').search

# postfix mail log
# groups = (queue id, message id)
get_mid2qid = re.compile(
    r'postfix/cleanup.*: ([0-9A-F]+): message-id=<([^>]+)>').search

# postfix mail log
# groups = (queue id, host, ip, user)
get_qid2user = re.compile(
    r'postfix/smtpd.*: ([0-9A-F]+): client=(\S*)\[([\d\.]*)\].*sasl_username=([^@\s]+)').search

# postfix mail log
# groups = (queue id, from address, num recipients)
get_qid2from = re.compile(
    r'postfix/qmgr.*: ([0-9A-F]+):.*from=<([^>]*)>.*nrcpt=(\d+)').search

class SmtpClient(object):
    '''Contains the hostname and ip of an SMTP client.

    Compares equal to another SmtpClient if their top- and second-level domain
    names match (so all SmtpClients with hostname=*.example.net will compare
    equal). This is to collapse SMTP client entries during scan_logs(); for
    example, legitimate connections from multiple google.com addresses for
    users sending mail from Gmail via our SMTP servers.
    '''

    def __init__(self, hostname, ip):
        self.hostname = hostname
        self.ip = ip
        parts = hostname.rsplit('.', 2)
        if len(parts) >=2:
            self.sldn = '.'.join(parts[-2:-1])
        else:
            self.sldn = ip

    def __eq__(self, other):
        return type(self) is type(other) and self.sldn == other.sldn

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.sldn)

    def __str__(self):
        return "%s[%s]" % (self.hostname, self.ip)

def scan_logs(maillogpath, mailboxlogpath, timeinterval=0, whitelist=None):
    '''
    This covers two attack vectors:

    1. Via ZWC. Use mailbox log to map message IDs to users, then use mail log
       postfix/cleanup lines to map queue IDs via message IDs to users. 
    2. Via SMTP. Use mail log postfix/smtpd lines to map queue IDs to users.
       Also keep track of the different hosts the user connects from.

    Once queue IDs are mapped to users, use mail log postfix/qmgr lines to
    count how many messages were sent by each user and record any outside
    from addresses.

    Returns (counts, outside, user2host).
    '''
    if whitelist is None:
        whitelist = []

    # maps username -> msg count
    counts = collections.defaultdict(int)
    # maps (username, fromaddr) -> msg count for outside addresses
    outside = collections.defaultdict(int)
    # maps username -> {smtp client hostname, ip}
    user2host = collections.defaultdict(set)

    mid2user = {}
    qid2user = {}

    maillog = open(maillogpath)
    mailboxlog = open(mailboxlogpath)

    if timeinterval:
        maillog.seek(0, 2)
        mailboxlog.seek(0, 2)
        time.sleep(timeinterval * 60)

    # Mapping of message IDs to users, for those using ZWC, etc.
    for l in mailboxlog:
        m = get_mid2user(l)
        if m:
            user, messageid = m.groups()
            user = user.lower()
            mid2user[messageid] = user

    for l in maillog:
        # Mapping of queue IDs to users, for direct smtp
        m = get_qid2user(l)
        if m:
            queueid, host, ip, user = m.groups()
            user = user.lower()
            qid2user[queueid] = user
            user2host[user].add(SmtpClient(host, ip))
            continue

        # Mapping of queue IDs via message IDs to users, for ZWC, etc.
        m = get_mid2qid(l)
        if m:
            queueid, messageid = m.groups()
            if messageid in mid2user:
                qid2user[queueid] = mid2user[messageid]
            elif queueid not in qid2user:
                qid2user[queueid] = 'Unknown'
            continue

        # Mapping of messages (from address and count)
        # via queue IDs to users.
        m = get_qid2from(l)
        if m:
            queueid, fromaddr, num_recipients = m.groups()
            # just use lowercase version of fromaddr
            fromaddr = fromaddr.lower()
            num_recipients = int(num_recipients)

            if queueid not in qid2user:
                # Log entries for message are split between runs--ignore
                continue
            user = qid2user[queueid]

            # At this point, the following are possible:
            #
            # 1. username and fromaddr
            #    Normal; log it
            # 2. username, no fromaddr
            #    Set fromaddr to mailer-daemon and log it
            # 3. no username, fromaddr
            #    Can happen (e.g. CalendarInviteForwardSender); don't log,
            #    since they would all be for user 'Unknown'
            # 4. no username, no fromaddr
            #    Don't log, for same reason

            if user == 'Unknown':
                continue
            if not fromaddr:
                fromaddr = 'mailer-daemon'

            # check for outside address and update count
            if (
                fromaddr != 'mailer-daemon'
                and not fromaddr.endswith(MY_DOMAIN)
                and fromaddr not in whitelist
                ):
                outside[(user, fromaddr)] += num_recipients

            # update individual count
            counts[user] += num_recipients

    return counts, outside, user2host

def check_threshold(senders, threshold, message=""):
    '''Print a message if the counts in senders exceed threshold.

    senders -- iterable of tuples (sender, count)
    threshold -- if a count exceeds this, print "count: sender"
    message -- if any count exceeds threshold, print this first

    The current implementation prints elements in descending order of count.
    '''
    # sort senders based on each element's count (which is its second item)
    senders = sorted(senders, key=itemgetter(1), reverse=True)

    # only proceed if the first element's count is greater than the threshold
    if senders and senders[0][1] >= threshold:
        if message:
            print message
        for sender, count in senders:
            if count < threshold:
                break # since the list is sorted, we're done
            print '%d:\t%s' % (count, sender)

def main(options):

    # Open the whitelist file, but ignore it if we can't
    try:
        whitelistfile = open(options.whitelist)
        whitelist = whitelistfile.read().lower().split('\n')
    except IOError:
        whitelist = None

    counts, outside, user2host = scan_logs(
        options.maillog, options.mailboxlog,
        options.timeinterval, whitelist
    )

    # sort on messages sent (second field), most to least
    counts = sorted(counts.iteritems(), key=itemgetter(1), reverse=True)
    for sender, count in counts:
        msgs_per_minute = count / (options.timeinterval or 5)
            
        # lock account if more than lock threshold
        if msgs_per_minute > options.lock:
            print 'LOCKING %s %d messages sent/minute' % (
                sender, msgs_per_minute
            )
            if not options.test:
                # do account lock here
                pass
            else:
                lock_account(sender, count)
        # warn if more than warning threshold
        elif msgs_per_minute > options.warn and not options.quiet:
            print 'WARNING %s %d messages sent/minute' % (
                sender, msgs_per_minute
            )
        else: # since the list is sorted, we're done
            break

    # The remaining notifications are warning-only.
    if not options.quiet:
        # outside from addresses
        check_threshold(
            outside.iteritems(),
            options.fromthreshold,
            '\nAlert: more than %d messages sent from outside address'
                % options.fromthreshold
        )

        # multiple SMTP clients
        check_threshold(
            ((user, len(hosts)) for user, hosts in user2host.iteritems()),
            options.clientwarn,
            '\nAlert: more than %d SMTP clients for user' % options.clientwarn
        )

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option(
        '--maillog',
        dest='maillog',
        help='postfix maillog (default %default)',
        default='/var/log/syslog/mail.log'
        )
    parser.add_option(
        '--mailboxlog',
        dest='mailboxlog',
        help='zimbra mailboxlog (default %default)', 
        default='/opt/zimbra/log/mailbox.log'
        )
    parser.add_option(
        '--whitelist',
        dest='whitelist',
        help='whitelist for outside from addrs (default %default)',
        default='/usr/local/etc/badspammer/whitelist.txt'
        )
    parser.add_option(
        '--quiet', '-q',
        dest='quiet',
        help='suppress warning messages',
        default=False,
        action='store_true'
        )
    parser.add_option(
        '--warn', dest='warn',
        help='warn after X messages per minute (default %default)',
        default=100,
        type='int'
        )
    parser.add_option(
        '--lock',
        dest='lock',
        help='lock account after X messages per minute (default %default)',
        default=1000,
        type='int'
        )    
    parser.add_option(
        '--timeinterval', 
        dest='timeinterval',
        help='monitor for X minutes (default %default, 0 to read current log)',
        default=5,
        type='int'
        )
    parser.add_option(
        '--fromthreshold',
        dest='fromthreshold',
        help='display outside from addrs if > X messages (default %default)',
        default=10,
        type='int'
        )
    parser.add_option(
        '--clientwarn',
        dest='clientwarn',
        help='warn if > X different SMTP client hosts (default %default)',
        default=20,
        type='int'
        )
    parser.add_option(
        '-t',
        '--test',
        dest='test',
        help="test mode (don't lock accounts)",
        default=False, action='store_true'
        )

    options, args = parser.parse_args()
    main(options)
