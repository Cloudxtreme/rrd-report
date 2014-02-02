# -*- coding: utf-8 -*-

import ctypes
from ctypes.wintypes import *
import socket
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import os
import time
import sys
import pickle
from ConfigParser import SafeConfigParser


MAX_INTERFACE_NAME_LEN = 2**8
MAXLEN_PHYSADDR = 2**3
MAXLEN_IFDESCR = 2**8
TCP_TABLE_OWNER_PID_LISTENER = 3

HOUR = 0
DAY = 1
WEEK = 2

steps = [ "1:500", "1:600", "6:700" ]

def send_mail(text=""):

    open_ports = get_ports()
    ports = pickle.load(open("tcp_ports", "rb"))

    table = """ Open Ports:<br><br>
           <table cellspacing="15">
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Description</th>
                </tr>
            """
    for p in open_ports:

        if p in ports:
            table += "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (p, ports[p][0], ports[p][1])
        else:
            table += "<tr><td>%s</td><td></td><td></td></tr>" % (p)


    parser = SafeConfigParser()
    parser.read("stats.conf")

    msg = MIMEMultipart('related')
    msg['Subject'] = "Traffic report from %s" % (socket.getfqdn())
    msg['From'] = parser.get('email', 'from')
    msg['To'] = parser.get('email', 'to')
    msg.preamble = 'This is a multi-part message in MIME format.'

    body = """
           %s<br><br> <img src="cid:graph_packets"><br><br>
           <img src="cid:graph_conns"><br><br>
           <img src="cid:graph_bandwidth"><br><br>%s</table>""" % (text, table)
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


# Reference for these data structures may be found:
# http://msdn.microsoft.com/en-us/library/aa916357.aspx

class MIB_TCPSTATS(ctypes.Structure):

    _fields_ = [
            ("dwRtoAlgorithm", DWORD),
            ("dwRtoMin", DWORD),
            ("dwRtoMax", DWORD),
            ("dwMaxConn", DWORD),
            ("dwActiveOpens", DWORD),
            ("dwPassiveOpens", DWORD),
            ("dwAttemptFails", DWORD),
            ("dwEstabResets", DWORD),
            ("dwCurrEstab", DWORD),
            ("dwInSegs", DWORD),
            ("dwOutSegs", DWORD),
            ("dwRetransSegs", DWORD),
            ("dwInErrs", DWORD),
            ("dwOutRsts", DWORD),
            ("dwNumConns", DWORD)
    ]


class MIB_UDPSTATS(ctypes.Structure):

    _fields_ = [

            ("dwInDatagrams", DWORD),
            ("dwNoPorts", DWORD),
            ("dwInErrors", DWORD),
            ("dwOutDatagrams", DWORD),
            ("dwNumAddrs", DWORD)
    ]


 
class MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", WCHAR * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", DWORD),
        ("dwType", DWORD),
        ("dwMtu", DWORD),
        ("dwSpeed", DWORD),
        ("dwPhysAddrLen", DWORD),
        ("bPhysAddr", BYTE * MAXLEN_PHYSADDR), 
        ("dwAdminStatus", DWORD),
        ("dwOperStatus", DWORD),
        ("dwLastChange", DWORD),
        ("dwInOctets", DWORD),
        ("dwInUcastPkts", DWORD),
        ("dwInNUcastPkts", DWORD),
        ("dwInDiscards", DWORD),
        ("dwInErrors", DWORD),
        ("dwInUnknownProtos", DWORD),
        ("dwOutOctets", DWORD),
        ("dwOutUcastPkts", DWORD),
        ("dwOutNUcastPkts", DWORD),
        ("dwOutDiscards", DWORD),
        ("dwOutErrors", DWORD),
        ("dwOutQLen", DWORD),
        ("dwDescrLen", DWORD),
        ("bDescr", ctypes.c_byte * MAXLEN_IFDESCR), 
    ]
 

class MIB_IFTABLE(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IFROW * 128),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
            ("dwState", DWORD),
            ("dwLocalAddr", DWORD),
            ("dwLocalPort", DWORD),
            ("dwRemoteAddr", DWORD),
            ("dwRemotePort", DWORD),
            ("dwOwningPid", DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
            ("dwNumEntries", DWORD),
            ("table", MIB_TCPROW_OWNER_PID * 128),
    ]


def get_stats():

    iphlpapi = ctypes.windll.Iphlpapi

    tcpstats = MIB_TCPSTATS()
    udpstats = MIB_UDPSTATS()
    iphlpapi.GetTcpStatisticsEx(ctypes.byref(tcpstats), socket.AF_INET)
    iphlpapi.GetUdpStatisticsEx(ctypes.byref(udpstats), socket.AF_INET)

    iftable = MIB_IFTABLE()
    dwSize = DWORD(0)

    # first call gets dwSize
    iphlpapi.GetIfTable('', ctypes.byref(dwSize), 0)
    iphlpapi.GetIfTable(ctypes.byref(iftable), ctypes.byref(dwSize), 0)

    bps = []
    for row in iftable.table:
        if row.dwType == 6 and row.dwInOctets > 0:
            bps.append(repr(row.dwInOctets))
            bps.append(repr(row.dwOutOctets))
            break

    tcp = (repr(tcpstats.dwInSegs), repr(tcpstats.dwOutSegs))
    udp = (repr(udpstats.dwInDatagrams), repr(udpstats.dwOutDatagrams))
    return tcp, udp, repr(tcpstats.dwCurrEstab), bps


def get_ports():

    iphlpapi = ctypes.windll.Iphlpapi

    dwSize = DWORD(0)
    table = MIB_TCPTABLE_OWNER_PID()

    # first call to get dwSize
    iphlpapi.GetExtendedTcpTable('', ctypes.byref(dwSize), 0, 
                                    socket.AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)
    iphlpapi.GetExtendedTcpTable(ctypes.byref(table), ctypes.byref(dwSize), 
                                    0, socket.AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)

    ports = [ str(x.dwLocalPort) for x in table.table if x.dwLocalPort != 0 ]
    ports.sort(key=float)

    return ports


def init_db():
    
    parser = SafeConfigParser()
    parser.read("stats.conf")
    freq = parser.getint("rrd", "frequency")

    cmd = ".\\RRDTool\\rrdtool.exe create stats.rrd " \
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

    cmd  = ".\\RRDTool\\rrdtool.exe update stats.rrd "\
            "N:%s:%s:%s:%s:%s:%s:%s" % (tcp[0], tcp[1], udp[0], udp[1], conns, bps[0], bps[1])
    os.system(cmd)


def generate_graphs(start_time):

    # packets per second
    cmd = ".\\RRDTool\\rrdtool.exe graph packets.png " \
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
            "DEF:in_tcp=stats.rrd:in_pps:AVERAGE "\
            "DEF:out_tcp=stats.rrd:out_pps:AVERAGE "\
            "DEF:in_udp=stats.rrd:in_dps:AVERAGE "\
            "DEF:out_udp=stats.rrd:out_dps:AVERAGE "\
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
    cmd = ".\\RRDTool\\rrdtool.exe graph conns.png " \
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
            "DEF:conns=stats.rrd:conns:AVERAGE "\
            "LINE2:conns#CC3300:\"Connections  \" " \
            "GPRINT:conns:LAST:\"Current\:%8.2lf\"  " \
            "GPRINT:conns:AVERAGE:\" Average\:%8.2lf\"  " \
            "GPRINT:conns:MAX:\" Maximum\:%8.2lf\l\"  "

    os.system(cmd)

    # bandwidth
    cmd = ".\\RRDTool\\rrdtool.exe graph bps.png " \
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
            "DEF:in_bps=stats.rrd:in_bps:AVERAGE "\
            "DEF:out_bps=stats.rrd:out_bps:AVERAGE "\
            "AREA:in_bps#00CC00:\"Inbound Bps  \" " \
            "GPRINT:in_bps:LAST:\" Current\:%8.2lf %s\" " \
            "GPRINT:in_bps:AVERAGE:\" Average\:%8.2lf %s\" " \
            "GPRINT:in_bps:MAX:\" Maximum\:%8.2lf %s\l\" " \
            "LINE2:out_bps#003399:\"Outbound Bps  \" " \
            "GPRINT:out_bps:LAST:\"Current\:%8.2lf %s\" " \
            "GPRINT:out_bps:AVERAGE:\" Average\:%8.2lf %s\" " \
            "GPRINT:out_bps:MAX:\" Maximum\:%8.2lf %s\l\" "

    os.system(cmd)


def update_progress(progress):
    bar = "\rProgress: |%s| %.2f%% complete" % ('█' * int(progress * 50), progress * 100)
    print(bar, end="")
    sys.stdout.flush()


if __name__ == "__main__":

    if os.path.isfile('stats.rrd'):
        os.remove('stats.rrd')

    parser = SafeConfigParser()
    parser.read("stats.conf")
    init_db()
    start_utime = int(time.time())

    freq = parser.getint("rrd", "frequency")
    cycles = parser.getint("rrd", "cycles")
    if freq == DAY:
        cycles *= 60
    elif freq == WEEK:
        cycles *= 1440

    start_time = time.strftime("%m/%d %I:%M %p")

    print("Gathering data...")

    for x in range(cycles):
        update()
        update_progress(float(x + 1)/cycles)

        if x is not (cycles - 1):
            time.sleep(60)

    print("\n")
    end_time = time.strftime("%m/%d %I:%M %p")
    timezone = time.strftime("%Z")

    msg = "Averages for %s to %s  (%s):\n\n" % (start_time, end_time, timezone)

    generate_graphs(start_utime)
    send_mail(msg)

    os.remove('packets.png')
    os.remove('conns.png')
    os.remove('bps.png')

    print("DONE!")
