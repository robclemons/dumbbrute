#! /usr/bin/env python3

from distutils.core import setup, Extension

brutus = Extension("brutus", libraries=["crypt"], sources=["brutus.c"])

setup(	name="brutus",
		version="0.0",
		description="a simple linux password bruteforcer",
		author="Geremy Condra",
		author_email="debatem1@gmail.com",
		url="geremycondra.net",
		scripts=["dumbbrute"],
		ext_modules=[brutus]
)
