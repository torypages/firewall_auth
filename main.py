from configparser import ConfigParser
from pprint import pprint
import argparse
import email
import gnupg
import iptc
import logging
import random
import re
import smtplib
import string
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('fwauth')

parser = ConfigParser()
parser.read('config.ini')

email_server = parser.get('email', 'server')
email_username = parser.get('email', 'username')
email_password = parser.get('email', 'password')
email_allowed_incoming = parser.get('email', 'allowed_incoming')

gnupg_home = parser.get('gnupg', 'home')
gnupg_username = parser.get('gnupg', 'username')
gnupg_passphrase = parser.get('gnupg', 'passphrase')
gnupg_allowed_fingerprints = parser.get('gnupg', 'allowed_fingerprints').split()
gpg = gnupg.GPG(gnupghome=gnupg_home)

smtp_server = parser.get('smtp', 'server')
smtp_port = parser.get('smtp', 'port')
smtp_username = parser.get('smtp', 'username')
smtp_password = parser.get('smtp', 'password')
smtp_allowed_outgoing = parser.get('smtp', 'allowed_outgoing').split()

table = iptc.Table(iptc.Table.FILTER)
table.autocommit = False

input_chain = iptc.Chain(table, "INPUT")
output_chain = iptc.Chain(table, "OUTPUT")
forward_chain = iptc.Chain(table, "FORWARD")

ip_re = """(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"""

# Override iptc.Rule toString with something useful in this application
def rule_tostring(x):
    src_ip = x.src.split('/')[0]
    port_str = ' '.join([i.dport for i in x.matches])
    protocol = x.protocol
    r = "src: {}, port: {}, protocol: {}".format(src_ip, port_str, protocol)
    return r
iptc.Rule.__str__ = rule_tostring

def extract_msg(raw_msg_parts, uid):
    def text_plain(i):
        return (i.get_content_maintype() == 'text' and
                i.get_content_subtype() == 'plain')
    msg_parts = raw_msg_parts.get_payload()
    if isinstance(msg_parts, str):
        msg = msg_parts
    else:
        raw_msg = next(i for i in msg_parts if text_plain(i))
        msg = raw_msg.get_payload()
    return msg, raw_msg_parts

def test_fingerprint(fingerprint, gnupg_allowed_fingerprints):
    if fingerprint and not fingerprint in gnupg_allowed_fingerprints:
        raise Exception("Fingerprint not allowed")
    elif not fingerprint:
        raise Exception("No fingerprint")

def extract_header_data(received_header):
    logger.debug("Received Header:")
    logger.debug(str(received_header))
    ip = None
    hostname = None
    header_re = ("""from (?P<hostname>.*?)\s.*?\[{ip_re}\].*\)"""
                 .format(ip_re=ip_re))
    header_search = re.search(header_re, received_header)
    if header_search:
        hostname = header_search.group('hostname')
        ip = header_search.group('ip')
        logger.info("IP from header: {}".format(ip))
    return ip, hostname 

def text_to_consider(decrypted_data):
    msg_text = str(decrypted_data.data, 'utf-8')
    lines = msg_text.splitlines()
    first_line = lines[0] if len(lines) else ''
    first_line = first_line.lower()
    # argument parsing expects arguments to be padded by spaces
    # and if an argument occurs immediately, this
    # parsing breaks
    # same for the end
    first_line = " {} ".format(first_line)
    return first_line

def extract_first_line_data(first_line):
    revoke = False
    ip = None
    logger.debug("First line: {}".format(first_line))
    fl_search = re.search(".*\s{}\s.*".format(ip_re), first_line)
    if fl_search:
        ip = fl_search.group('ip')
        logger.info("First line IP: {}".format(ip))
    revoke = ' rm ' in first_line
    return revoke, ip

def reconcile_ip(ip, fl_ip):
    if ip and fl_ip:
        logger.info("Overriding header IP {} with first line IP {}"
                    .format(ip, fl_ip))
        return fl_ip
    else:
        logger.info("Using header IP: {}".format(ip))
        return ip

def apply_first_line_instructions(fl_revoke, first_line, ip):
    action_func = delete_rule if fl_revoke else add_rule
    apply_default = True
    for port in [22, 443]:
        padded_port_str = ' {} '.format(port)
        if padded_port_str in first_line:
            port_str = str(port)
            rule = build_rule(ip, port_str, 'tcp')
            action_func(rule, force=False)
            apply_default = False

    # default to https
    if apply_default:
        rule = build_rule(ip, '443', 'tcp')
        action_func(rule, force=False)

def process_msg_data(data, uid):
    msg, raw_msg_parts  = extract_msg(data, uid)
    decrypted_data = gpg.decrypt(msg, passphrase=gnupg_passphrase)
    if not decrypted_data.status.lower() == 'decryption ok':
        raise Exception('Decryption status not ok')
    fingerprint = decrypted_data.pubkey_fingerprint
    test_fingerprint(fingerprint, gnupg_allowed_fingerprints)
    received_header = next(reversed(raw_msg_parts.get_all('Received')))
    ip, hostname = extract_header_data(received_header=received_header)
    first_line = text_to_consider(decrypted_data)
    fl_revoke, fl_ip = extract_first_line_data(first_line)
    ip = reconcile_ip(ip, fl_ip)
    apply_first_line_instructions(fl_revoke, first_line, ip)
    logger.info("Done processing one message.")
 
def base_fw_rules():
    input_chain.flush()
    output_chain.flush()
    forward_chain.flush()

    rule = iptc.Rule()
    rule.in_interface = 'lo'
    target = iptc.Target(rule, 'ACCEPT')
    rule.target = target
    input_chain.append_rule(rule)

    rule = iptc.Rule()
    rule.out_interface = 'lo'
    target = iptc.Target(rule, 'ACCEPT')
    rule.target = target
    output_chain.append_rule(rule)

    rule = iptc.Rule()
    target = iptc.Target(rule, 'ACCEPT')
    rule.target = target
    match = iptc.Match(rule, "state")
    match.state = "RELATED,ESTABLISHED"
    rule.add_match(match)
    input_chain.append_rule(rule)

    rule = iptc.Rule()
    target = iptc.Target(rule, 'ACCEPT')
    rule.target = target
    match = iptc.Match(rule, "state")
    match.state = "RELATED,ESTABLISHED"
    rule.add_match(match)
    output_chain.append_rule(rule)

    input_chain.set_policy('DROP')
    output_chain.set_policy('ACCEPT')
    forward_chain.set_policy('DROP')

    table.commit()
    table.refresh()


def build_rule(ip, port, protocol):
    rule = iptc.Rule()
    rule.src = ip
    rule.protocol = protocol
    match = iptc.Match(rule, protocol)
    match.dport = port
    rule.add_match(match)
    rule.target = iptc.Target(rule, "ACCEPT")
    return rule

def action_rule(rule, action):
    action(rule)
    retry = 0
    while True:
        try:
            table.commit()
            table.refresh()
            logger.info("Table commit success")
            break
        except iptc.ip4tc.IPTCError as e:
            msg = str(e)
            if retry > 5:
                logger.error("No more retries")
                break
            if 'temporarily' in msg.lower():
                logger.info("iptables busy, will retry")
                retry += 1
                time.sleep(4)
                continue

def rule_exists(rule):
    return rule in input_chain.rules

def add_rule(rule, force=False):
    if not rule_exists(rule) or force:
        logger.info("ADDING RULE: {}".format(rule))
        action = input_chain.append_rule
        action_rule(rule, action)
    else:
        logger.info("Won't add rule that already exists.")
        logger.info(rule)
    
def delete_rule(rule, force=False):
    if rule_exists(rule) or force:
        logger.info("DELETING RULE: {}".format(rule))
        action = input_chain.delete_rule
        action_rule(rule, action)
    else:
        logger.info("Can't delete rule that doesn't exist.")
        logger.info(rule)

def randomness(x):
    return ''.join([random.choice(string.printable) for _ in range(x)])

def send_email(to, contents):
    if not to in smtp_allowed_outgoing:
        logger.error("{} not allowed as outgoing email".format(to))
        return

    logger.info("Sending email to: {}".format(to))
    logger.info("Contents: {}".format(contents))

    # Don't end up with repeated encrypted text
    contents = "{}\n\nrandomtext\n{}".format(contents, randomness(100))

    server = smtplib.SMTP(smtp_server, int(smtp_port))
    server.starttls()
    server.login(smtp_username, smtp_password)
     
    encrypted_msg = gpg.encrypt(contents, to, passphrase=gnupg_passphrase)
    if not encrypted_msg.status == 'encryption ok':
        logger.error(encrypted_msg.stderr)
        return
    server.sendmail(email_username, to, str(encrypted_msg))
    server.quit()

def process_mail2(imap):
    logger.info("Processing folder.")
    unseen = imap.search('UNSEEN')
    for uid in unseen:
        try:
            data = imap.fetch(uid, 'BODY.PEEK[]')
            raw_msg_parts = email.message_from_bytes(data[uid][b'BODY[]'])
            from_address = email.utils.parseaddr(raw_msg_parts.get('from'))
            from_email = from_address[1]
            if from_email not in email_allowed_incoming:
                raise Exception("From {} address not allowed".format(from_email))
            process_msg_data(raw_msg_parts, uid)
            # but what success?
            send_email(from_email, 'success')
        except Exception as e:
            logger.error(e)
            import traceback
            traceback.print_exc()
            send_email(from_email, str(e))
            try:
                pass
            except Exception as e:
                logger.error(e)
            finally:
                traceback.print_exc()
        finally:
            # always mark as seen even on failure
            imap.add_flags(uid, '\SEEN')

def listen():
    import eventlet
    imapclient = eventlet.import_patched('imapclient')
    while True:
        imap = imapclient.IMAPClient(email_server, use_uid=True, ssl=True)
        result = imap.login(email_username, email_password)
        result = imap.select_folder('INBOX')
        process_mail2(imap)
        logger.info("Done initial process, starting monitoring")
        while True:
            imap.idle()
            result = imap.idle_check(5 * 60)
            if result:
                imap.idle_done()
                process_mail2(imap)
            else:
                imap.idle_done()
                imap.noop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # These are just for testing/dev
    parser.add_argument('--base-rules', action='store_true')
    parser.add_argument('--add-rule', action='store_true')
    parser.add_argument('--delete-rule', action='store_true')
    parser.add_argument('--check-exists', action='store_true')
    parser.add_argument('--ip')
    parser.add_argument('--port')
    parser.add_argument('--protocol')
    parser.add_argument('--imap-listen', action='store_true')
    parser.add_argument('--send-email', action='store_true')
    args = parser.parse_args()

    if args.base_rules:
        base_fw_rules()
    elif args.add_rule:
        rule = build_rule(args.ip, args.port, args.protocol)
        add_rule(rule)
    elif args.delete_rule:
        rule = build_rule(args.ip, args.port, args.protocol)
        delete_rule(rule)
    elif args.check_exists:
        rule = build_rule(args.ip, args.port, args.protocol)
        print(rule in input_chain.rules)
    elif args.imap_listen:
        listen()
    elif args.send_email:
        send_email(smtp_allowed_outgoing[0], 'cool')
    else:
        base_fw_rules()
        listen()

