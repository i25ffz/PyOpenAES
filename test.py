import openaes

open('README.enc', 'w').write(openaes.encrypt(open('key_256').read(), open('README').read()))
open('README.dec', 'w').write(openaes.decrypt(open('key_256').read(), open('README.aes').read()))
print open('README.dec').read()
