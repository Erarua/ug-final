import os
import datetime
import time

header = 0xe0
cid_len = 20
client_cid = os.urandom(cid_len)
server_cid = os.urandom(cid_len)
version = 0x00000000
supported_version = [0x6b3343cf, 0x00000001, 0xff000020, 0xff00001f, 0xff00001e, 0xff00001d]

# st = datetime.datetime.now()
st = time.perf_counter()

masking_key_len = 4
masking_key = os.urandom(masking_key_len)

# print("client_cid: ", bytes(client_cid).hex())
# print("server_cid: ", bytes(server_cid).hex())
# print("masking_key: ", masking_key.hex())

i = 0
client_cid_new = bytearray(cid_len)
while i < cid_len:
    client_cid_new[i] = client_cid[i] ^ masking_key[i%4]
    i += 1
server_cid_new = bytearray(cid_len)
while i < 2*cid_len:
    server_cid_new[i-cid_len] = server_cid[i-cid_len] ^ masking_key[i%4]
    i += 1

# print("client_cid: ", client_cid_new.hex())
# print("server_cid: ", server_cid_new.hex())

# et = datetime.datetime.now()
# time.sleep(0.000000001)
et = time.perf_counter()
print("duration: ", et-st)