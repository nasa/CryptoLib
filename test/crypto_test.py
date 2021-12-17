# Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
# All Foreign Rights are Reserved to the U.S. Government.
# 
# This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
# including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
# of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
# documentation will conform to the program, or any warranty that the software will be error free.
# 
# In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
# consequential damages, arising out of, resulting from, or in any way connected with the software or its
# documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
# from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.
# 
# ITC Team
# NASA IV&V
# jstar-development-team@mail.nasa.gov

# 
# Connect to cFS via UDP to CI_Lab and TO_Lab to send and receive messages
# used to verify the SDLS-EP protocol via Interoperability Testing
#

import binascii
import os
import signal
import socket
import struct
import sys

def signal_term_handler(signale,frame):
    print '\nExiting gracefully...\n'
    ci.close()
    to.close()
    sys.exit(0)

class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

signal.signal(signal.SIGINT, signal_term_handler)

# Get PWD
pwd = os.getcwd() + "/"

# Setup CI UDP
UDP_IP_CI = "127.0.0.1"
UDP_PORT_CI = 1234
ci = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Setup TO UDP
UDP_IP_TO = "127.0.0.1"
UDP_PORT_TO = 1235
to = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
to.bind((UDP_IP_TO, UDP_PORT_TO))
to.settimeout(5.0)

python_files = [
                pwd+"sdls_ep_interop/tc4.txt",
                pwd+"sdls_ep_interop/tc5.txt",
                pwd+"sdls_ep_interop/tc6.txt",
               ]

print color.BOLD + '\nBegin Testing the Cryptography Library...' + color.END

for file_name in python_files:
    with open(file_name) as f:
        print file_name + " has been loaded!"
        print color.YELLOW + "Typically flight software must be rebooted now!\n" + color.END
        for line in f:	
            # Determine line
            if line.startswith("Number = "):
                number = line[9:]
                #sys.stdout.write(line[9:len(line)] + ") ")
                #print line[9:] + " "
            if line.startswith("Description = "):
                description = line[14:]
                #sys.stdout.write(line[14:len(line)])
                #print line[14:] + " "
            if line.startswith("TC = "):
                tc = line[5:]
            if line.startswith("TM = "):
                tm = line[5:]
                print number.replace("\n","\t") + description
                raw_input("Press ENTER to proceed...\n")
                if len(tc) > 2:
                    # Send TC to CI_Lab
                    print tc
                    ci.sendto(binascii.unhexlify(tc[0:len(tc)-1]), (UDP_IP_CI,UDP_PORT_CI))
                if len(tm) > 2:
                    # Receive TM from TO_Lab
                    #print tm
                    try:
                        data, addr = to.recvfrom(10000);
                    except socket.timeout:
                        print color.RED + 'ERROR: TO_Lab timeout exceeded!' + color.END
                        os.kill(os.getpid(), signal.SIGINT)
                    if len(data) == 0:
                        print color.RED + 'ERROR: received no data from TO_Lab when response expected!' + color.END
                        os.kill(os.getpid(), signal.SIGINT)
                    else:
                        if tm[0:len(tm)-1] != binascii.hexlify(data[0:len(tm)-1]):
                            print color.RED + 'ERROR: received TM data did not match expected!' + color.END
                            print len(binascii.hexlify(data))
                            print '\t received TM: ' + binascii.hexlify(data)
                            print len(tm)
                            print '\t expected TM: ' + tm
                            os.kill(os.getpid(), signal.SIGINT)

print >> sys.stderr, "Out of data, exiting gracefully..."
ci.close()
to.close()