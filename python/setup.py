from distutils.core import setup, Extension
import os.path

kw = {
	'name':"PyOpenAES",
	'version':"0.10.0",
	'description':"OpenAES cryptographic library for Python.",
	'ext_modules':[
		Extension(
			'openaes',
			include_dirs = ['../inc', '../src/isaac'],
			# define_macros=[('ENABLE_PYTHON', '1')],
			sources = [
				os.path.join('oaes_py.c'),
				os.path.join('../src/oaes_lib.c'),
				os.path.join('../src/oaes_base64.c'),
				os.path.join('../src/isaac/rand.c')
			]
		)
	]
}

setup(**kw)