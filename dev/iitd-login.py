#! /usr/bin/python3

# Author      : Original code by J Phani Mahesh
# Description : A pure python3 utility to log into IITD proxy servers.
#
# Logs to syslog by default.  With '-d' logs to stdout

import urllib.request, urllib.parse, urllib.error, ssl
import sys, syslog
import time
import traceback
from argparse import ArgumentParser
from datetime import datetime
from html.parser import HTMLParser

SLEEP_TIMER = 100
LOGIN_ATTEMPTS = 5
MAX_CONN_ATTEMPTS = 10
PROXY_BASE_URL = 'proxy61.iitd.ac.in'
PROXY_PORT = 3128
address = 'https://' + PROXY_BASE_URL + '/cgi-bin/proxy.cgi'

userid = None
passwd = None

def nologger(s):
    pass

logger = syslog.syslog
debug_logger = nologger

def log_to_file(fo, s):
    print(s, end='', file=fo, flush=True)

def read_login_creds_if_none_supplied():
    import getpass
    global userid, passwd

    if not sys.stdin.isatty() and (userid == None or passwd == None):
        logger("userid or passwd is missing, and stdin is not tty.  Exiting!\n")
        sys.exit(1)

    if userid == None:
        userid = input('userid: ')
    if passwd == None:
        passwd = getpass.getpass('passwd: ')

# create a SSL context which doesn't perform cert validation
sslctx = ssl.create_default_context()
sslctx.check_hostname = False
sslctx.verify_mode = ssl.CERT_NONE

# wrapper which uses our ssl context
opener = lambda address: urllib.request.urlopen(address, context=sslctx)

# proxy opener for testing connection
proxy = urllib.request.ProxyHandler({'http': 'http://{}:{}'.format(PROXY_BASE_URL, PROXY_PORT) })
proxyopener = urllib.request.build_opener(proxy)

# global login/logout data
loggedin_data = None
logout_data = None

# POST-able binary stream maker
yunoencode = lambda form: urllib.parse.urlencode(form).encode('ascii')

class MyHTMLParser(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.input = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attrsdict = {}
            for name,value in attrs:
                attrsdict[name] = value
            self.input.append(attrsdict)

    def get_input_tags(self):
        return self.input

def parse_login_page(html):
    htmlparser = MyHTMLParser(html)
    for tag in htmlparser.get_input_tags():
        if 'name' in tag and tag['name'] == 'sessionid':
            sessionid = tag['value']
            return sessionid
    else:
        logger("Error parsing html: {}.\n".format(html.replace('\n', ' ')))
        raise ValueError("sessionid not found in html")

def login():
    # load login page
    logger("Reading login page...\n")
    try:
        html = opener(address).read().decode('utf-8')
    except Exception as e:
        logger("Error retrieving the login page.\n")
        logger("Exception: {}\n".format(str(e)))
        raise ValueError("Error retrieving the login page")

    # save html
    debug_logger("==login_page== {}: {}\n".format(str(datetime.now()), html))

    # parse html
    logger("Parsing html...\n")
    sessionid = parse_login_page(html)
    logger("Session id is : {}\n".format(sessionid))

    # form data
    login_form    = { 'sessionid':sessionid, 'action':'Validate', 'userid':userid, 'pass':passwd }
    loggedin_form = { 'sessionid':sessionid, 'action':'Refresh' }
    logout_form   = { 'sessionid':sessionid, 'action':'logout' }

    # POST-able binary stream data
    login_data = yunoencode(login_form)

    logger("Sending login request...\n")
    try:
        response = None
        response = opener(urllib.request.Request(address,login_data)).read().decode('utf-8')
    except Exception as e:
        logger("Error submitting login form\n")
        logger("Exception: {}\n".format(str(e)))
        if response is not None:
            logger("Response: {}\n".format(response))
        raise ValueError("Error submitting login form")

    debug_logger("==login_response== {}:\n{}\n".format(str(datetime.now()), response))

    if "successfully" not in str(response):
      if "already logged in" in str(response):
        logger("Already logged in... logging out\n")
        logout()
      else:
        logger("Unexpected page returned: {}.\n".format(response))
        raise ValueError("Unexpected page")

    # successful login; set loggedin and logout data
    global loggedin_data, logout_data
    loggedin_data = yunoencode(loggedin_form)
    logout_data = yunoencode(logout_form)

def try_login(max_attempts):
    for i in range(max_attempts):
        try:
            logger("Trying login (attempt #{}/{})...\n".format(i+1,max_attempts))
            login()
            test_connection()
        except Exception as e:
            logger("Exception: {}\n".format(str(e)))
            logger("Login attempt failed. {} attempts left.\n".format(max_attempts-i-1))
            continue # retry
        return True  # return if didn't fail
    # max attempts reached
    logger("try_login: Max login attempts reached.\n")
    return False

def test_connection():
  try:
    response = proxyopener.open("http://example.com")
    response_text = response.read().decode('utf-8')
    debug_logger("==test_connnection== {}:\n{}\n".format(str(datetime.now()), response_text))
  except Exception as e:
    logger("Connection test request failed\n")
    logger("Exception: {}\n".format(str(e)))
    raise ValueError("Connection test request failed")

  if response.status != 200:
    logger("Non-200 status received from http://example.com\n")
    raise ValueError("Non-200 status received from http://example.com")
  if "Example Domain" not in response_text:
    logger("http://example.com page didn't match\n")
    raise ValueError("Example page didn't match")
    
def refresh():
  if loggedin_data is None:
      logger("refresh() called without logging-in\n")
      raise ValueError("Logged-in data not available.")
  try:
    response = opener(urllib.request.Request(address,loggedin_data))
  except Exception as e:
    logger("Refresh request failed\n")
    logger("Exception: {}\n".format(str(e)))
    raise ValueError("Refresh request failed")
  response_text = response.read().decode('utf-8')
  debug_logger("==refresh== {}:\n{}\n".format(str(datetime.now()), response_text))
  if response.status != 200 or "successfully" not in response_text:
    logger("Response code: {}\n".format(response.status))
    logger("Response: {}\n".format(response_text))
    raise ValueError("Refresh failed")

def logout():
  global logout_data
  if logout_data is None:
      logout_form = { 'sessionid':'', 'action':'logout' } # use empty sessionid
      logout_data = yunoencode(logout_form)
  try:
    response = opener(urllib.request.Request(address,logout_data))
  except Exception as e:
    logger("Logout request failed\n")
    logger("Exception: {}\n".format(str(e)))
    raise ValueError("Logout request failed")
  response_text = response.read().decode('utf-8')
  debug_logger("==logout== {}:\n{}\n".format(str(datetime.now()), response_text))
  if response.status != 200 or "Session Terminated" not in response_text:
      logger("Logout failed: {}\n".format(response.status))
      return False
  else:
      logger("Logged out successfully\n")
      return True

def main():
    global debug_logger, logger

    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", help="produce operational logs to stdout", action="store_true")
    parser.add_argument("-D", "--deep_debug", help="log network requests to provided filename", type=str, default="")
    args = parser.parse_args()

    if args.debug:
        logger = lambda x : print("{}: {}".format(str(datetime.now()),x), end='')
    if args.deep_debug != "":
        fo = open(args.deep_debug, "w")
        debug_logger = lambda s: log_to_file(fo, s)
        logger("Logging accesses to {}\n".format(args.deep_debug))

    read_login_creds_if_none_supplied()

    attempt = 0

    logger("Login address: {}\n".format(address))
    logger("Logging in...\n")
    if not try_login(LOGIN_ATTEMPTS):
        sys.exit(1)
    logger("Logged in.\n")

    # Keep logged-in
    try:
        while True:
            time.sleep(SLEEP_TIMER)
            try:
              refresh()
              logger("Heartbeat sent\n")
              test_connection()
            except (ValueError, urllib.error.URLError) as e:
                logger("Lost connection: {}\n".format(str(e)))
                attempt = attempt + 1
                if attempt > MAX_CONN_ATTEMPTS:
                    logger("Giving up...\n")
                    raise ValueError("Maximum login attempts reached")
                # logout and then try login again
                logger("Waiting for {} seconds...\n".format(SLEEP_TIMER))
                time.sleep(SLEEP_TIMER)
                logger("Logging out first...\n")
                try:
                  logout()
                except Exception as e:
                  logger("Exception: {}".format(str(e)))
                logger("Logging in again...\n")
                if not try_login(LOGIN_ATTEMPTS):
                    sys.exit(1)
                logger("Logged in.\n")
    except:
        logger("Traceback:\n{}\n".format(traceback.format_exc()))
        logger("Logging out...\n")
        if not logout():
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
  main()
