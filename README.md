# DNS-client
In this project, you will design and implement a simplified DNS client that can manually construct and send DNS query messages to a DNS server, then receive and parse the response to extract the resolved IP address. While tools like nslookup and dig offer this functionality from the command line, this assignment challenges you to build the DNS query process from the ground up—giving you a practical understanding of the DNS protocol and how its messages are formatted and exchanged over the network.

Your DNS client will consist of three primary components:

Constructing the DNS Query:
The client must accept two command-line arguments: a domain name (e.g., gmu.edu) and a query type (A for IPv4 or AAAA for IPv6). Based on these inputs, the program will construct a DNS query message following the protocol specifications outlined in RFC 1035. This involves assembling a header section (with fields like ID, QR, RD, QDCOUNT) and a question section (including QNAME, QTYPE, and QCLASS). You will manually encode these fields into a binary message format, taking care to follow the precise layout and bit structures expected by DNS servers.

Sending the Query over UDP:
Once the query message is constructed, the client must establish a UDP socket and send the message to a public DNS server—specifically, Google’s DNS server at IP address 8.8.8.8. Your program must handle network unreliability by implementing a timeout and retry mechanism. If no response is received within 5 seconds, the client should resend the query. A maximum of 3 attempts should be made before the program exits with a timeout error.

Receiving and Parsing the Response:
Upon receiving a response, the client must decode it by parsing the binary response structure into its components—header, question, answer, and potentially authority and additional sections. For each field in the response, the client must extract and display the values in a clear <field, value> format on the command line. In particular, the answer section may contain one or more Resource Records (RRs), from which the resolved IP address will be obtained (in the RDATA field). Responses must be validated (e.g., matching ID field, checking for errors via RCODE), and malformed responses should be reported.

The client will be tested against both IPv4 and IPv6 queries. This means the message format must correctly accommodate both A (Type 1) and AAAA (Type 28) queries. The QNAME field must follow the proper label encoding (length-prefixed format), and all data must be packed in network byte order.

To aid in debugging and testing, you are encouraged to use Wireshark to inspect the raw DNS packets being transmitted and received. This will help confirm that the message structure complies with DNS protocol expectations.

In order to compile and run my program you simply do: 
- python3 my-dns-client.py <host-name> A

Example:
- python3 my-dns-client.py google.com A
- python3 my-dns-client.py gmu.edu A
- python3 my-dns-client.py facebook.com A
- python3 my-dns-client.py youtube.com A
