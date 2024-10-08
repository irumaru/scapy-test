from scapy.all import *

def print_pkt(pkt):
  print("---summary---")
  print(pkt.summary())
  print("---show---")
  print(pkt.show())
  print("---raw---")
  print(raw(pkt))
  print("")

  print("---type/Ether---")
  print(type(pkt))
  print("---type/IP---")
  print(type(pkt["IP"]))

  if "TCP" in pkt["IP"]:
    print("---type/TCP---")
    print(type(pkt["IP"]["TCP"]))
  elif "UDP" in pkt["IP"]:
    print("---type/UDP---")
    print(type(pkt["IP"]["UDP"]))
  else:
    print("---type/None---")
    exit()
  print("")

  print("---IP/len---")
  print(pkt["IP"].len)
  print("---IP/src---")
  print(pkt["IP"].src)
  print("---IP/dst---")
  print(pkt["IP"].dst)

  print("")

  if "TCP" in pkt["IP"]:
    print("---TCP/sport---")
    print(pkt["IP"]["TCP"].sport)
    print("---TCP/dport---")
    print(pkt["IP"]["TCP"].dport)
  elif "UDP" in pkt["IP"]:
    print("---UDP/sport---")
    print(pkt["IP"]["UDP"].sport)
    print("---UDP/dport---")
    print(pkt["IP"]["UDP"].dport)

  print("")

  print("---IP/ls---")
  print(ls(pkt["IP"]))

  print("-------------------------------")
  exit()
  #pkt.show()

sniff(iface="eth0", prn=print_pkt)
