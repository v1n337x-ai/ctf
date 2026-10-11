EXHIBIT A  capture-0814.pcap.txt   session timeline
EXHIBIT B  shred-scan/              shredded pages, one strip per line
EXHIBIT C  transfers.csv            money movement, same night

The sealed-edge blob the insider left in the capture is bound to the trail.
An analyst who can state the whole trail gets it open. The key is built
from these five facts, joined with "|" and in this order:

    authority | ledger total | duplicated counterparty | duplicated amount |
    sum of every transfer

Seeded with sha256, then a splitmix64 stream, xored against the blob.
