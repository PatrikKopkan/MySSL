from OpenSSL import crypto, SSL
from os.path import join
import random

with open("CA_certificates/CA-cert.key") as CA:
    CA_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, CA.read())

with open("CA_certificates/CA-cert.crt") as cert:
    CA_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.read())



def verify_cert(cert):
    try:
        store = crypto.X509Store()
        store.add_cert(CA_cert)

        store_ctx = crypto.X509StoreContext(store, cert)

        store_ctx.verify_certificate()

        return True
    except Exception as e:
        print(e)
        return False




if __name__ == '__main__':
    CN = input("Zadejte název certifikátu: ")
    pubkey = "%s.crt" % CN #replace %s with CN
    privkey = "%s.key" % CN # replcate %s with CN

    pubkey = join(".", pubkey)
    privkey = join(".", privkey)

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    serialnumber=random.getrandbits(64)


    cert = crypto.X509()
    cert.get_subject().ST = input("Stát (formát př. US, CZ): ")
    cert.get_subject().L = input("Město: ")
    cert.get_subject().O = input("Organizace: ")
    cert.get_subject().OU = input("Organizační jednotka: ")
    cert.get_subject().CN = CN
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)#315360000 is in seconds.
    cert.set_issuer(CA_cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(CA_privkey, 'sha512')
    pub=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv=crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    open(pubkey,"wt").write(pub.decode("utf-8"))
    open(privkey, "wt").write(priv.decode("utf-8") )

