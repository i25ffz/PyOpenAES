import openaes

open('README.aes', 'w').write(openaes.encrypt(open('key_256').read(), open('README').read()))
print openaes.decrypt(open('key_256').read(), open('README.aes').read())
