#!/root/py3/bin/python

import socket
import ipaddress
import smtplib
from dns import resolver, reversename
from email.message import EmailMessage


def check_if_ipv6(ip_address):
  try:
    addr = ipaddress.IPv6Address(ip_address)
    return True
  except ipaddress.AddressValueError:
    return False


def get_network_from_ipaddress(ip_address = "0.0.0.1"):
  ''' convert the ip_address to hostname '''
  if check_if_ipv6(ip_address):                                                         # ipv6 we do not handle
    hostname = "ipv6.unresolvable"
    return(hostname, ip_address)
  try:
    socket.inet_aton(ip_address)                                                        # check if it is ipv4 \
    hostname = str(resolver.query(reversename.from_address(ip_address),"PTR")[0])[:-1]  # make src_ip fqdn, otherwise suffix loss
  except KeyError:
    ip_address = "0.0.0.1"                                                              # no valid ipv4 address (my be ipv6)
    hostname = "unresolvable.somedomain"                                                # failed, unresolvable, assign something
  except OSError:                                                                       # it was no ipv4      /
    ip_address = "0.0.0.1"                                                              # failed, assign something
    hostname = "unresolvable.somedomain"                                                # failed, unresolvable, assign something
  except resolver.NXDOMAIN:                                                             # reverse resolve impossible
    hostname = "ipv4.unresolvable"                                                      # failed, unresolvable, assign something
  return(hostname, ip_address)


def get_network_from_hostname(hostname = "unresolvable.somedomain"):
  ''' convert the hostname to ip address '''
  try:
    hostname = hostname.lower()                                                         # convert hostname to lowercase
    ip_address = socket.gethostbyname(hostname)                                         # make it ipv4
  except socket.gaierror:                                                               # reverese can't be made
    ip_address = "0.0.0.1"                                                              # failed, unresolvable, assign something
  ''' convert the ip address to hostname '''
  try:
    hostname = str(resolver.query(reversename.from_address(ip_address),"PTR")[0])[:-1]  # make src_ip fqdn, otherwise suffix loss
  except resolver.NXDOMAIN:                                                             # reverse resolve impossible (put error)
    hostname = "unresolvable"
  return(hostname, ip_address)


def send_alert(ALERT_FILE, ALERT_NAME, ALERT_SENDER, ALERT_RECIPIENT):
  with open(ALERT_FILE, "r") as file:

    msg = EmailMessage()
    msg.set_content(file.read())

    msg['Subject'] = 'OIKB ALERT: ' + ALERT_NAME
    msg['From'] = ALERT_SENDER
    msg['To'] = ALERT_RECIPIENT

    s = smtplib.SMTP('localhost')
    s.send_message(msg)
    s.quit()
