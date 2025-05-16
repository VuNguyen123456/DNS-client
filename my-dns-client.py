import struct
import socket
import secrets
import sys


def build_query():
    #header
    id = secrets.token_bytes(2)#random number
    QR = '0'
    OPCODE = '0000'
    AA = '0'
    TC = '0'
    RD = '1'
    RA = '0'
    Z = '000'
    RCODE = '0000'
    flagsString = QR + OPCODE + AA + TC + RD + RA + Z + RCODE # concat them into string so that can convert them into bytes
    flags = int(flagsString, 2).to_bytes(2, byteorder = 'big')

    qdCount = b'\x00\x01'
    anCount = b'\x00\x00'
    nsCount = b'\x00\x00'
    arCount = b'\x00\x00'

    #Question section
    #QNAME = sys.argv[1]
    QNAME = b''.join(bytes([len(part)]) + part.encode() for part in sys.argv[1].split('.')) + b'\x00'
    #gmu.edu: split them with "." -> loop over 1st element and 2nd element -> calculate the length of its part -> convert into bytes -> combine the 2 part ->join into 1 -> mark the end

    if sys.argv[2] == "A":  # IPv4: 1
        QTYPE = b'\x00\x01'
    elif sys.argv[2] == "AAAA":  # IPv6: 28
        QTYPE = b'\x00\x1C'
    else:
        pass
    QCLASS = b'\x00\x01'



    query = id + flags + qdCount + anCount + nsCount + arCount + QNAME + QTYPE + QCLASS 
    print("Preparing DNS query..")
    return query
    #return query.hex()


def send_query():
    query = build_query()
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mySocket.settimeout(5)
    #mySocket.bind(('8.8.8.8', 53))

    print("Contacting DNS server..")
    print("Sending DNS query..")

    for i in range(3):
        try:
            mySocket.sendto(query,('8.8.8.8', 53))
            print(f"DNS response received (attempt {i+1} of 3)")
            # print("Processing DNS response..")
            receiveAndResponse(mySocket)
            return None
        except mySocket.timeout:
            print(f"Attemp {i+1}")
            continue
    else:
        print("Timeout....")
    mySocket.close()
    return None

def receiveAndResponse(mySocket):
    if mySocket is None:
        return None
    print("Processing DNS response..")
    print("----------------------------------------------------------------------------")
    reponse_data, _ = mySocket.recvfrom(512)
    # Analyze it
    # Each thing is 2 bytes
    # Header 
    id = reponse_data[0:2].hex()
    flags   = struct.unpack(">H",reponse_data[2:4])[0]
    qdCount = struct.unpack(">H",reponse_data[4:6])[0]
    anCount = struct.unpack(">H",reponse_data[6:8])[0]
    nsCount = struct.unpack(">H",reponse_data[8:10])[0]
    arCount = struct.unpack(">H",reponse_data[10:12])[0]
    # Flags
    qr = (flags >> 15) & 0x1 #make sure it's not filled with 1 if right shift sign
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = (flags & 0xF)
    print("header.ID = " + id)
    print("header.QR = " + str(qr))
    print("header.OPCODE = " + str(opcode))
    print("header.AA = " + str(aa))
    print("header.TC = " + str(tc))
    print("header.RD = " + str(rd))
    print("header.RA = " + str(ra))
    print("header.Z = " + str(z))
    print("header.RCODE = " + str(rcode))
    print("header.QDCOUNT = " + str(qdCount))
    print("header.ANCOUNT = " + str(anCount))
    print("header.NSCOUNT = " + str(nsCount))
    print("header.ARCOUNT = " + str(arCount))
    # Question
    offset = 12 # 6 thing each is 2 bytes
    Qname, offset = handleNameOffset(reponse_data,offset)
    Qtype = struct.unpack(">H",reponse_data[offset:offset+2])[0]
    Qclass = struct.unpack(">H",reponse_data[offset+2:offset+4])[0]
    offset += 4
    print("question.QNAME = " + str(Qname))
    print("question.QTYPE = " + str(Qtype))
    print("question.QCLASS = " + str(Qclass))
    if rcode != 0:
        print("Error in rcode")
        return None
    # Answer 1 or more
    for i in range(anCount):
        #name, offset = handleNameOffset(reponse_data, offset)
        offset += 2 #Skiped
        typeOfRR = struct.unpack(">H",reponse_data[offset:offset+2])[0]
        classInRR = struct.unpack(">H",reponse_data[offset+2:offset+4])[0]
        ttl = struct.unpack(">I",reponse_data[offset+4:offset+8])[0] # 4 bytes =>>>>
        rdlength = struct.unpack(">H",reponse_data[offset+8:offset+10])[0]
        # rdata = struct.unpack(">H",reponse_data[offset+10:offset+14])[0]#IP address also 4 byte
        # offset += 14
        offset += 10
        rdata = reponse_data[offset:offset+rdlength]
        resolvedIpAddress = ".".join(str(byte) for byte in rdata)
        offset += rdlength
        #print("answer.NAME = " + str(name))
        print("answer.NAME = skip")
        print("answer.TYPE = " + str(typeOfRR))
        print("answer.CLASS = " + str(classInRR))
        print("answer.TTL = " + str(ttl))
        print("answer.RDLENGTH = " + str(rdlength))
        print("answer.RDATA = " + str(resolvedIpAddress))
        print("-------------------------------------")
    print("----------------------------------------------------------------------------")

    #Parse in hexa

    # print("header.ID = " + id)
    # print("header.QR = " + qr)
    # print("header.OPCODE = " + opcode)
    # print("header.AA = " + aa)
    # print("header.TC = " + tc)
    # print("header.RD = " + rd)
    # print("header.RA = " + ra)
    # print("header.Z = " + z)

    # print("header.QDCOUNT = " + qdCount)
    # print("header.ANCOUNT = " + anCount)
    # print("header.NSCOUNT = " + nsCount)
    # print("header.ARCOUNT = " + arCount)

    # print("question.QNAME = " + Qname)
    # print("question.QTYPE = " + Qtype)
    # print("question.QCLASS = " + Qclass)



def handleNameOffset(reponse_data, offset):
    labels = []
    while True:
        sizeOfLabel = reponse_data[offset]
        if sizeOfLabel == 0:
            offset += 1
            break
        else: 
            offset += 1 # Skip over size telling bytes
            temp = (reponse_data[offset:offset+sizeOfLabel].decode("utf-8"))
            labels.append(temp)
            offset += sizeOfLabel
    return ".".join(labels), offset

def main():
    if len(sys.argv) != 3:
        #return None
        sys.exit(1)

    send_query()
    # receiveAndResponse(send_query())


if __name__ == "__main__":
    main()

