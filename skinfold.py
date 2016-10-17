import nfqueue
from scapy.all import *
import os
import binascii

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE "

# If you want to use it for MITM :
iptablesr = "iptables -A FORWARD -p tcp --dport 2000 -j NFQUEUE"
iptablesr1 = "iptables -A FORWARD -p tcp --sport 2000 -j NFQUEUE"
debug_flag=0
src_ip=''
firstpacket_flag=1


def debuglog(printstuff):
    global debug_flag
    if (debug_flag > 0):
           print time.strftime("%c") + " :  " + printstuff




debuglog("Adding iptable rules :")
debuglog(iptablesr)
debuglog(iptablesr1)
os.system(iptablesr)
os.system(iptablesr1)


#os.system("sysctl net.ipv4.ip_forward=1")





def callback(payload):

    # Here is where the magic happens.
    global src_ip
    global firstpacket_flag
    inject = 0
    data = payload.get_data()
    pkt = IP(data)
    packedIP = socket.inet_aton(get_if_addr('tun0'))

    if firstpacket_flag:
       src_ip = socket.inet_aton(pkt[IP].src)
       firstpacket_flag=0

    if TCP in pkt and hasattr (pkt[TCP], 'load'):
       #hexdump(pkt[TCP].payload)
       payload_len_before = len(pkt)
       pktpayload = pkt[TCP].load

       if re.search(src_ip.encode('hex'),pktpayload.encode('hex')):
          #hexdump(pkt[TCP].load)
          debuglog( " PACKET BEFORE MODIFICATION TCPIPV4:" )
          #pkt.show
          #debuglog(str(pkt.show()))

          pktpayload = re.sub(src_ip.encode('hex'),packedIP.encode('hex'),pktpayload.encode('hex'))

          debuglog("Found it, replaced DeviceIPV4Address in pktpayload-")
          inject = 1

       if inject:
          del pkt[IP].chksum
          del pkt[TCP].chksum

          debuglog("injecting packet!")
          pkt[TCP].load = binascii.unhexlify(pktpayload)
          payload_len_after = len(pkt)
          #if payload_len_before > payload_len_after:
          #payload_dif = payload_len_before - payload_len_after
          #else:

          payload_dif =  payload_len_after - payload_len_before
          debuglog("Payload_diff: " + str(payload_dif))
          pkt[IP].len = pkt[IP].len - payload_dif

          #hexdump(pkt[TCP].payload)
          debuglog("PACKET AFTER MODIFICATION :")
          #Line is buggy below, displays when flag is 0
          #debuglog(str(pkt.show()))
          #pkt.show()

          payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(str(pkt)))


def main():
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    pid = os.getpid()
    #op = open("/var/run/skinfold.py.pid","w")
    #op.write("%s" % pid)
    #op.close()



    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        debuglog("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')


if __name__ == "__main__":
    main()
