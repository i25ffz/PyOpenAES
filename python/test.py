import openaes

open('README.enc', 'w').write(openaes.encrypt(open('key_256').read(), open('README').read()))
open('README.dec', 'w').write(openaes.decrypt(open('key_256').read(), open('README.enc').read()))
print open('README.dec').read()
