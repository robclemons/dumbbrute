/************************************************
brutus.h

Written by Robbie Clemons and Geremy Condra
Licensed under GPLv3
Released 20 April 2010

This file defines the core functions of a stupid
simple bruteforcer for linux passwords. It is
designed to be used in conjunction with brutus.py.
*************************************************/

#include <Python.h>
#include <crypt.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#ifndef BRUTUS_H
#define BRUTUS_H

#define MAX_PASSWORD_LENGTH 100
#define MAX_CHARSET_LENGTH 500
#define MAX_HASH_LENGTH 500
#define MAX_SALT_LENGTH 500

#define BRUTE_RUNNING 0
#define BRUTE_DONE 1
#define BRUTE_UNINITIALIZED -1

// defines the structure needed by the Python object
// to control each thread.
typedef struct {
	PyObject_HEAD
	// controls access to the thread itself
	pthread_t thread_id;
	// flag for the thread's final state
	pthread_mutex_t done_mutex;
	int done;
	char password[MAX_PASSWORD_LENGTH];
	// arguments to the bruteforce function
	uint64_t start;
	uint64_t stop;
	char charset[MAX_CHARSET_LENGTH];
	uint64_t charset_len;
	size_t list_size;
	char (*word_array)[MAX_PASSWORD_LENGTH];
	char hash[MAX_HASH_LENGTH];
	uint64_t hash_len;
	char salt[MAX_SALT_LENGTH];
	uint64_t salt_len;
	// diagnostics and testing
	time_t start_time;
	time_t end_time;
} Brute;
	
// frees allocated memory when thread is cancelled
void clean_thread(void *args);

// gets the nth digit of x expressed in base b
uint64_t nth_digit(uint64_t x, uint64_t n, uint64_t b);

// turns the given integer into a password consisting of elements from charset
void nth_password(char *pw, uint64_t n, uint64_t charset_len, char *charset);

// runs through all passwords between start and stop, comparing
// crypt(pw, salt) to the given hash and returning a match if found
// returns a NULL if it isn't.
char *bruteforce(Brute *b);


// wraps the bruteforcer for threading
void *bruteforce_wrapper(void *args) ;

// Allocates the new brute. Also creates the new thread.
PyObject *Brute_new(PyTypeObject *type, PyObject *args, PyObject *kwargs);

// Handles the init function, which starts the whole thing running
int Brute_init(Brute *self, PyObject *args);

// Gets the answer if this Brute has it, returns '' if the
// computation is done and we didn't find it, and False if we
// aren't done yet.
// Remember to set the XMLRPC server to handle this correctly.
PyObject *Brute_done(PyObject *self, PyObject *args);

// returns the timing data for this run
PyObject *Brute_diagnostic(PyObject *self, PyObject *args);

// END HIM
PyObject *Brute_kill(PyObject *self, PyObject *args);

// Kills the brute- mostly in case the answer is found elsewhere
void Brute_dealloc(Brute *self);

#endif
