from Cryptodome.PublicKey import ECC
import tenseal as ts
# generate client keys
for i in range (512):
	key = ECC.generate(curve='P-256')
	hdr = 'client'+str(i)+'.pem'
	f = open(hdr, 'wt')
	f.write(key.export_key(format='PEM'))
	f.close()
#
key = ECC.generate(curve='P-256')
with open('decryption_server_sk.pem', 'wt') as f:
	f.write(key.export_key(format='PEM'))
with open('decryption_server_pk.pem', 'wt') as f:
	f.write(key.public_key().export_key(format='PEM'))
