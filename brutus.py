#! /usr/bin/env python3

"""
brutus.py

Written by Geremy Condra and Robbie Clemons
Licensed under GPLv3
Released 16 April 2010
"""

from sys import argv
from subprocess import getstatusoutput as run
from multiprocessing import cpu_count
from _thread import start_new_thread
from time import sleep
from math import ceil

from xmlrpc.client import ServerProxy
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

from brutus import Brute

class Bruteforcer:

	brutes = {}
		
	def heartbeat(self):
		return True

	def version():
		return "0"
		
	def bruteforce(self, start, end, charset, hash_value):
		# get the salt from the hash
		if "rounds" in hash_value:
			# if the number of rounds is specified
			salt = '$'.join(hash_value.split("$")[:4])
		else:
			# number of rounds is unspecified
			salt = '$'.join(hash_value.split("$")[:3])
		# start the brute
		brute = Brute(start, end, charset, hash_value, salt)
		self.brutes[str(id(brute))] = brute
		return str(id(brute))
		
	def done(self, job):
		return self.brutes[job].done()
		
	def benchmark(self, job):
		return self.brutes[job].benchmark()
		
	def kill(self, job):
		return self.brutes[job].kill()
		

def num_passwords(charset, maximum_password_length):
	possibleNum = 0
	for each in range(1, maximum_password_length+1):
		possibleNum += (len(charset) ** each)
	return possibleNum
	
def start_server():
	host = ''
	port = 8000
	done = False
	server = SimpleXMLRPCServer((host, port), SimpleXMLRPCRequestHandler, allow_none=True)
	bruteforcer = Bruteforcer()
	server.register_instance(bruteforcer)
	server.register_function(cpu_count)
	server.serve_forever()

def start_local(num_threads, max_pw_len, charset, hash_value):
	start_new_thread(start_server, tuple())
	proxy = ServerProxy("http://localhost:8000")
	if not proxy.heartbeat():
		raise Exception("Could not connect to local server")
	start = 0
	jobs = []
	end = num_passwords(charset, max_pw_len)
	hashes_per_brute = ceil((end - start)/num_threads)
	for i in range(num_threads):
		tmp = start
		start += hashes_per_brute
		jobs.append(proxy.bruteforce(tmp, start, charset, hash_value))
	all_done = False
	while not all_done:
		sleep(5)
		all_done = True
		for job in jobs:
			result = proxy.done(job)
			if not result[0]:
				all_done = False
			elif len(result[1]):
				return result
	return False
	
def start_master(charset, addr_list, hash_value):
	
	# create the proxy list
	proxy_list = [ServerProxy(addr) for addr in addr_list]
	# make sure all servers are alive
	for proxy in proxy_list:
		if not proxy.heartbeat():
			raise Exception("Could not connect to remote server %s" % proxy)
			
	# get the count of cpus in the cluster
	cpus_per_machine = {proxy: proxy.cpu_count() for proxy in proxy_list}
	total_cpus = sum(cpus_per_machine.values())
	# now start the bruteforcing
	current_threads = 0
	for proxy in proxy_list:
		proxy_capacity = cpus_per_machine[proxy]
		start_new_thread(bruteforce_wrapper, (proxy, current_threads, current_threads + proxy_capacity, total_cpus, charset, hash_value))
		current_threads += proxy_capacity
		
	# poll the machines on a 1 minute interval asking for results
	while not done:
		sleep(5)
	
	for proxy in proxy_list:
		proxy.stop()

	
if __name__ == "__main__":
	
	if len(argv) == 1:
		start_server()
	elif len(argv) == 5:
		num_threads = int(argv[1])
		max_pass_len = int(argv[2])
		charset = argv[3]
		hash_value = argv[4]
		result = start_local(num_threads, max_pass_len, charset, hash_value)
		if result:
			print(result[1])
		else:
			print("The password was not found")		
	elif len(argv) == 6:
		charset = argv[1]
		ip_list = open(argv[2]).read().split()
		hash_value = argv[3]
		start_master(charset, ip_list, hash_value)
