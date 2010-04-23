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
	
def start_server(log_requests, port):
	host = ''
	done = False
	server = SimpleXMLRPCServer((host, port), SimpleXMLRPCRequestHandler,
			allow_none=True, logRequests=log_requests)
	bruteforcer = Bruteforcer()
	server.register_instance(bruteforcer)
	server.register_function(cpu_count)
	server.serve_forever()

def start_local(num_threads, max_pw_len, charset, hash_value, port, verbose):
	start_new_thread(start_server, (verbose, port))
	proxy = ServerProxy("http://localhost:" + str(port))
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
				return result[1]
	return False
	
def start_master(charset, max_pw_len, nodefile, hash_value):
	
	# create the proxy list
	addr_list = open(nodefile).readlines()
	proxy_list = [ServerProxy(addr) for addr in addr_list]
	# make sure all servers are alive
	for proxy in proxy_list:
		if not proxy.heartbeat():
			raise Exception("Could not connect to remote server %s" % proxy)
			
	# get the count of cpus in the cluster
	cpus_per_machine = {proxy: proxy.cpu_count() for proxy in proxy_list}
	total_cpus = sum(cpus_per_machine.values())
	# get the number of passwords and passwords/thread
	start = 0
	end = num_passwords(charset, max_pw_len)
	hashes_per_thread = ceil(end/total_cpus)
	
	# now start the bruteforcing
	results = []
	for proxy in proxy_list:
		proxy_capacity = cpus_per_machine[proxy]
		for i in range(proxy_capacity):
			tmp = start
			start += hashes_per_thread
			job_id = proxy.bruteforce(tmp, start, charset, hash_value)
			results.append((proxy, job_id))
		
	# poll the machines on a 1 minute interval asking for results
	password = ""
	still_running = True
	while still_running:
		sleep(10)
		still_running = False
		for proxy, job_id in results:
			status, password = proxy.done(job_id)
			if not status: still_running = True
			if password: break
	
	for proxy, job_id in results:
		proxy.kill(job_id)
		
	return password

	
if __name__ == "__main__":
	
	from optparse import OptionParser
	from string import ascii_lowercase
	
	parser = OptionParser()
	
	parser.add_option("-t", "--threads", dest="threads", type="int",
		help="The number of threads to run with", default=cpu_count())
	
	parser.add_option("-l", "--length", dest="length", type="int",
		help="The maximum password length to look for", default=8)
		
	parser.add_option("-c", "--charset", dest="charset",
		help="The set of possible characters in the password", default=ascii_lowercase)
		
	parser.add_option("-n", "--nodes", dest="nodes", default=False,
		help="File location containing a newline delimited list of compute nodes")
		
	parser.add_option("-p", "--port", dest="port", type="int",
		help="The port to contact the server on", default=8000)
		
	parser.add_option("-v", "--verbose", action="store_true", help="Emit server logs")

	opts, args = parser.parse_args()
	
	if not len(args):
		start_server(opts.verbose, opts.port)

	elif opts.nodes:
		retval = start_master(opts.charset, opts.length, opts.nodes, args[0])
		if retval: print(retval)
		else: print("The password was not found")
		
	else:
		result = start_local(opts.threads, opts.length, opts.charset, args[0], opts.port, opts.verbose)
		if result: print(result)
		else: print("The password was not found")
