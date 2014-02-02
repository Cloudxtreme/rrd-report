#!/usr/bin/env python
# -*- coding: utf-8 -*-

import smtplib
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.MIMEImage import MIMEImage
from ConfigParser import SafeConfigParser
import re
import socket
import os
import time
import subprocess
import sys
import pickle

HOUR = 0
DAY = 1
WEEK = 2

steps = [ "1:500" , "1:600", "6:700" ]

def send_mail(etc=""):

    open_ports = get_ports()

    ports = pickle.load(open("tcp_ports", "rb"))

    text = """ Open Ports:<br><br>
           <table cellspacing="15">
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                </tr>
            """

    for p in open_ports:

        text += "<tr><td>%s</td><td>%s</td></tr>" % (p, lsofi(p))


    parser = SafeConfigParser()
    parser.read("./stats.conf")

    msg = MIMEMultipart('related')
    msg['Subject'] = "Traffic report from %s" % (socket.getfqdn())
    msg['From'] = parser.get('email', 'from')
    msg['To'] = parser.get('email', 'to')
    msg.preamble = 'This is a multi-part message in MIME format.'

    body = """
           %s<br><br> <img src="cid:graph_packets"><br><br>
           <img src="cid:graph_conns"><br><br>
           <img src="cid:graph_bandwidth"><br><br>%s</table>""" % (etc, text)
    msgBody = MIMEText(body, 'html')
    msg.attach(msgBody)


    attachments = [ ('packets.png', 'graph_packets'), 
                    ('conns.png', 'graph_conns'),
                    ('bps.png', 'graph_bandwidth') ]

    for attachment in attachments:
        fp = open(attachment[0], 'rb')
        img = MIMEImage(fp.read())
        img.add_header('Content-ID', attachment[1])
        fp.close()
        msg.attach(img)

    s = smtplib.SMTP(parser.get('email', 'smtp_server'), parser.getint('email', 'port'))

    if parser.getboolean('email', 'auth'):
        s.ehlo()
    if parser.getboolean('email', 'use_tls'):
        s.starttls()
        s.ehlo()

    if parser.getboolean('email', 'auth'):
        s.login(parser.get('email', 'username'), parser.get('email', 'password'))

    s.sendmail(parser.get('email', 'from'), [parser.get('email', 'to')], msg.as_string())
    s.quit()


def get_stats():

    proc = open("/proc/net/snmp")
    data = proc.read()
    proc.close()

    match = re.search(r'Tcp:(\s\-?\d+){9} (\d+) (\d+)', data, re.M)
    in_tcp_pkts = match.group(2)
    out_tcp_pkts = match.group(3)
    tcp = (in_tcp_pkts, out_tcp_pkts)

    match = re.search(r'Udp: (\d+) \d+ \d+ (\d+)', data, re.M)
    in_udp_dgrams = match.group(1)
    out_udp_dgrams = match.group(2)
    udp = (in_udp_dgrams, out_udp_dgrams)

    match = re.search(r'Tcp:(\s\-?\d+){8} (\d+)', data, re.M)
    conns = match.group(2)


    proc = open("/proc/net/dev")
    data = proc.read()
    proc.close()

    match = re.findall(r'(.*?):\s?(\d+)(\s+\d+){7} (\d+)', data, re.M)
    bps = []
    for m in match:

        if not 'lo' in m[0] and m[1] != 0:
            bps.append(m[1])
            bps.append(m[3])
            break

    return tcp, udp, conns, bps

# lsof -i in python
def lsofi(port):

    handle = open('/proc/net/tcp', 'rb')
    data = handle.read()
    handle.close()

    hexport = "%04.X" % (int(port))

    
    regex = "\d:\s[0-9A-F]*?:%s.*?0A.*?\s+(\d+\s+){3}(\d+)" % hexport
    match = re.search(regex, data, re.M)
    inode = match.group(2)

    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue

        try:
            for fd in os.listdir('/proc/%s/fd' % pid):
                
                match = ':[%s]' % inode
                try:
                    if match in os.path.realpath('/proc/%s/fd/%s' % (pid, fd)):
                        handle = open('/proc/%s/status' % pid, "rb")
                        cmd = handle.read()
                        handle.close()
                        
                        exe = re.search(r'Name:\s+(\S+)', cmd, re.M)
                        return exe.group(1)
                except OSError:
                    continue
        except OSError:
            continue

    return "<i>unknown</i>"

# REGEX: r'(\S*)\s+(\d+).(\w+)\s+#?(\s.*)?'

# probably could go in get_stats but the return was getting messy and
# Python 2.4 doesn't have namedtuples
def get_ports():
    
    regex = r'\s*?\d+: .*?:([0-9A-F]*)\s[0-9A-F].*?:[0-9A-F].*?\s([0-9A-F]*)'
    proc = open("/proc/net/tcp")
    data = proc.read()
    proc.close()

    match = re.findall(regex, data, re.M)
    
    # remove dups
    match = list(set(match))

    # 0A indicates TCP connection is in LISTEN state
    ports = [ str(int(x[0], 16)) for x in match if x[1] == '0A' ] # hex -> dec
    ports.sort(key=float)

    return ports



# dont use pyRRD for portability
def init_db():
    
    parser = SafeConfigParser()
    parser.read("./stats.conf")
    freq = parser.getint("rrd", "frequency")

    cmd = "rrdtool create data.rrd " \
             "--step 60 " \
             "DS:in_pps:COUNTER:120:0:U " \
             "DS:out_pps:COUNTER:120:0:U " \
             "DS:in_dps:COUNTER:120:0:U " \
             "DS:out_dps:COUNTER:120:0:U " \
             "DS:conns:GAUGE:120:0:U " \
             "DS:in_bps:COUNTER:120:0:U " \
             "DS:out_bps:COUNTER:120:0:U " \
             "RRA:AVERAGE:0.5:%s " \
             "RRA:MAX:0.5:%s " \
             "RRA:LAST:0.5:%s"
    
    cmd = cmd % (steps[freq], steps[freq], steps[freq])
    os.system(cmd)


def update():

    tcp, udp, conns, bps = get_stats()

    cmd  = "rrdtool update data.rrd "\
            "N:%s:%s:%s:%s:%s:%s:%s" % (tcp[0], tcp[1], udp[0], udp[1], conns, bps[0], bps[1])
    os.system(cmd)


def generate_graphs(start_time):

    # packets per second
    cmd = "rrdtool graph packets.png " \
            "--title \"Packets per Second\" " \
            "--imgformat=PNG " \
            "--width 600 --height 100 " \
            "--base=1000 "\
            "--lower-limit 0 "\
            "--alt-autoscale-max " \
            "--rigid --slope-mode "\
            "--font TITLE:12 --font AXIS:8 --font LEGEND:10 --font UNIT:8 " \
            "--end=now --start=" + start_time + " " \
            "--color BACK#F0F0F0 --color CANVAS#FFFFFF --color FONT#000000 "\
            "DEF:in_tcp=data.rrd:in_pps:AVERAGE "\
            "DEF:out_tcp=data.rrd:out_pps:AVERAGE "\
            "DEF:in_udp=data.rrd:in_dps:AVERAGE "\
            "DEF:out_udp=data.rrd:out_dps:AVERAGE "\
            "LINE2:in_tcp#C35817:\"Inbound TCP Packets  \" " \
            "GPRINT:in_tcp:LAST:\" Current\:%8.2lf \" " \
            "GPRINT:in_tcp:AVERAGE:\"Average\:%8.2lf \" " \
            "GPRINT:in_tcp:MAX:\"Maximum\:%8.2lf \l\" "\
            "LINE2:out_tcp#E78A61:\"Outbound TCP Packets  \" " \
            "GPRINT:out_tcp:LAST:\"Current\:%8.2lf \" " \
            "GPRINT:out_tcp:AVERAGE:\"Average\:%8.2lf \" " \
            "GPRINT:out_tcp:MAX:\"Maximum\:%8.2lf \l\" "\
            "LINE2:in_udp#15317E:\"Inbound UDP Datagrams\" " \
            "GPRINT:in_udp:LAST:\" Current\:%8.2lf\"  " \
            "GPRINT:in_udp:AVERAGE:\" Average\:%8.2lf\"  " \
            "GPRINT:in_udp:MAX:\" Maximum\:%8.2lf\l\"  " \
            "LINE2:out_udp#3090C7:\"Outbound UDP Datagrams\" " \
            "GPRINT:out_udp:LAST:\"Current\:%8.2lf\"  " \
            "GPRINT:out_udp:AVERAGE:\" Average\:%8.2lf\"  " \
            "GPRINT:out_udp:MAX:\" Maximum\:%8.2lf\l\"  "

    os.system(cmd)

    # connections
    cmd = "rrdtool graph conns.png " \
            "--title \"Total Connections\" " \
            "--imgformat=PNG " \
            "--width 600 --height 100 " \
            "--base=1000 "\
            "--lower-limit 0 "\
            "--alt-autoscale-max " \
            "--rigid --slope-mode "\
            "--font TITLE:12 --font AXIS:8 --font LEGEND:10 --font UNIT:8 " \
            "--end=now --start=" + start_time + " " \
            "--color BACK#F0F0F0 --color CANVAS#FFFFFF --color FONT#000000 "\
            "DEF:conns=data.rrd:conns:AVERAGE "\
            "LINE2:conns#CC3300:\"Connections  \" " \
            "GPRINT:conns:LAST:\"Current\:%8.2lf\"  " \
            "GPRINT:conns:AVERAGE:\" Average\:%8.2lf\"  " \
            "GPRINT:conns:MAX:\" Maximum\:%8.2lf\l\"  "

    os.system(cmd)

    # bandwidth
    cmd = "rrdtool graph bps.png " \
            "--title \"Bytes per Second\" " \
            "--imgformat=PNG " \
            "--width 600 --height 100 " \
            "--base=1000 "\
            "--lower-limit 0 "\
            "--alt-autoscale-max " \
            "--rigid --slope-mode "\
            "--font TITLE:12 --font AXIS:8 --font LEGEND:10 --font UNIT:8 " \
            "--end=now --start=" + start_time + " " \
            "--color BACK#F0F0F0 --color CANVAS#FFFFFF --color FONT#000000 "\
            "DEF:in_bps=data.rrd:in_bps:AVERAGE "\
            "DEF:out_bps=data.rrd:out_bps:AVERAGE "\
            "AREA:in_bps#00CC00:\"Inbound Bps  \" " \
            "GPRINT:in_bps:LAST:\" Current\:%8.2lf %s\" " \
            "GPRINT:in_bps:AVERAGE:\" Average\:%8.2lf %s\" " \
            "GPRINT:in_bps:MAX:\" Maximum\:%8.2lf %s\l\" " \
            "LINE2:out_bps#003399:\"Outbound Bps  \" " \
            "GPRINT:out_bps:LAST:\"Current\:%8.2lf %s\" " \
            "GPRINT:out_bps:AVERAGE:\" Average\:%8.2lf %s\" " \
            "GPRINT:out_bps:MAX:\" Maximum\:%8.2lf %s\l\" "

    os.system(cmd)


# helper function for install_rrd
def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True, stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE) == 0


def update_progress(progress):
    bar = "\rProgress: |%s| %.2f %% complete" % ('█' * int(progress * 50), progress * 100)
    print bar,
    sys.stdout.flush()


if __name__ == "__main__":

    
    if os.path.isfile('data.rrd'):
        os.remove('data.rrd')

    parser = SafeConfigParser()
    parser.read("./stats.conf")
    init_db()
    start_utime = int(time.time())

    freq = parser.getint("rrd", "frequency")
    cycles = parser.getint("rrd", "cycles")
    if freq == DAY:
        cycles *= 60
    elif freq == WEEK:
        cycles *= 1440

    start_time = time.strftime("%m/%d %I:%M %p")

    print "Gathering data..."
    for x in range(cycles):
        update()
        update_progress(float(x + 1)/cycles)

        if x is not (cycles - 1):
            time.sleep(60)

    print "\n"
    end_time = time.strftime("%m/%d %I:%M %p")
    timezone = time.strftime("%Z")

    msg = "Data for %s to %s (%s):\n\n" % (start_time, end_time, timezone)

    generate_graphs(str(start_utime))
    send_mail(msg)

    os.remove('packets.png')
    os.remove('conns.png')
    os.remove('bps.png')

    print "DONE!"
