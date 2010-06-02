/************************************************
brutus.c

Written by Geremy Condra
Licensed under GPLv3
Released 20 April 2010

This file implements the core functions of a stupid
simple bruteforcer for linux passwords. It is
designed to be used in conjunction with brutus.py.
*************************************************/

#include "brutus.h"

/*************************************************
Code needed to actually do the bruteforcing
*************************************************/
uint64_t nth_digit(uint64_t x, uint64_t n, uint64_t base) {
	while(n--)
		x /= base;
	return x % base;
}

char *nth_password(uint64_t n, uint64_t charset_len, char *charset) {
	int i, j;
	// get the number of digits in n
	for(i=0; pow(charset_len, i) <= n; ++i)
		n -= pow(charset_len, i);

	// allocate space for output
	char *output = (char*)malloc(sizeof(char) * (i+1));
	bzero(output, i+1);
	
	// and fill it with the appropriate characters
	for(j=0; j < i; j++)
		output[j] = charset[nth_digit(n, j, charset_len)];
		
	return output;
}

char *bruteforce(uint64_t start, uint64_t stop, uint64_t charset_len, char *charset, uint64_t hash_len, char *hash, uint64_t salt_len, char *salt) {
	uint64_t n;
	struct crypt_data *data = {0};
	data = malloc(sizeof(*data));
	for(n=start; n <= stop; n++) {
		pthread_testcancel();
		char *pw = nth_password(n, charset_len, charset);
		data->initialized = 0;
		if(strcmp(crypt_r(pw, salt, data), hash) == 0)
			return pw;
		free(pw);
	}
	return NULL;
}

void *bruteforce_wrapper(void *args) {
	Brute *b = (Brute *)args;
	char *result = bruteforce(b->start, b->stop, b->charset_len, b->charset, b->hash_len, b->hash, b->salt_len, b->salt);
	pthread_mutex_lock(&(b->done_mutex));
	b->done = BRUTE_DONE;
	if(result) 
		strcpy(b->password, result);
	pthread_mutex_unlock(&(b->done_mutex));
	b->end_time = time(NULL);
	free(result);
	return NULL;
}

/****************************************************
Support code for Python bindings
****************************************************/

PyObject *Brute_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {

	// create the new Brute pointer
	Brute *self = (Brute *)type->tp_alloc(type, 0);

	// make sure it actually worked
	if (!self) {
		PyErr_SetString(PyExc_TypeError, "could not create Brute.");
		return NULL;
	}

	// initial set up of everything the structure needs.
	self->done = BRUTE_UNINITIALIZED;
	self->start = 0;
	self->stop = 0;
	self->charset_len = 0;
	self->hash_len = 0;
	self->salt_len = 0;	
	pthread_mutex_init(&(self->done_mutex), NULL);

	// cast and return
	return (PyObject *)self;
}


int Brute_init(Brute *self, PyObject *args) {
	const char *charset;
	const char *hash;
	const char *salt;
	PyObject *start;
	PyObject *end;
	if (!PyArg_ParseTuple(args, "OOs#s#s#",
					&start, 
					&end,
					&charset,
					&(self->charset_len),
					&hash,
					&(self->hash_len),
					&salt,
					&(self->salt_len)))
	{
		PyErr_SetString(PyExc_TypeError, "could not parse arguments");
		// XXX notice this flags errors on -1, not NULL!
		return -1;
	}

	// we have to do this to avoid 32 bit bullshit
	if (!PyLong_Check(start)) {
		PyErr_SetString(PyExc_TypeError, "start must be an integer argument");
		return -1;
	}
	if (!PyLong_Check(end)) {
		PyErr_SetString(PyExc_TypeError, "start must be an integer argument");
		return -1;
	}
		
	self->start = PyLong_AsUnsignedLongLong(start);
	self->stop = PyLong_AsUnsignedLongLong(end);
	
	memcpy(self->charset, charset, self->charset_len);
	memcpy(self->hash, hash, self->hash_len);
	memcpy(self->salt, salt, self->salt_len);		

	// set the done state
	self->done = BRUTE_RUNNING;

	// start the thread
	int dummy;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &dummy);
	pthread_create(&(self->thread_id), &attr, bruteforce_wrapper, (void*)self);
	
	// set the start time
	self->start_time = time(NULL);
	 
	// and go home
	return 0;	
}

PyObject *Brute_done(PyObject *self, PyObject *args) {
	// extract the internal Brute object
	Brute *b = (Brute *)self;

	// prepare the return object
	PyObject *retval = NULL;

	// get the done mutex
	pthread_mutex_lock(&(b->done_mutex));

	// check if we're done
	retval = Py_BuildValue("(i, s)", b->done, b->password);

	// unlock the mutex
	pthread_mutex_unlock(&(b->done_mutex));

	// go home
	return retval;
}

PyObject *Brute_diagnostic(PyObject *self, PyObject *args) {
	// extract the brute object
	Brute *b = (Brute *)self;
	if(b->done != BRUTE_DONE) {
		PyErr_SetString(PyExc_TypeError, "Brute is not done yet");
		return NULL;
	}
	// get the difference between its start time and
	// its end time
	double time_diff = difftime(b->end_time, b->start_time);
	// get the number of hashes it ran through
	uint64_t num_hashes = b->stop - b->start;
	// and return them
	return Py_BuildValue("(f, l)", time_diff, num_hashes);
}

PyObject *Brute_kill(PyObject *self, PyObject *args) {
	Brute *b = (Brute *)self;
	int value = pthread_cancel(b->thread_id);
	return Py_BuildValue("l", value);
}

void Brute_dealloc(Brute *self) {
	Py_TYPE(self)->tp_free((PyObject*)self);
}

PyMethodDef Brute_methods[] = {
	{"done", (PyCFunction)Brute_done, METH_VARARGS, "Checks to see if the Brute is done, and returns a password if it found it."},
	{"kill", (PyCFunction)Brute_kill, METH_VARARGS, "Ends the brute's life"},
	{"diagnostic", (PyCFunction)Brute_diagnostic, METH_VARARGS, "Tests to see how fast the brute is"},
	{NULL, NULL}
};

PyTypeObject BruteType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"brutus.Brute",             /*tp_name*/
	sizeof(Brute),             /*tp_basicsize*/
	0,                         /*tp_itemsize*/
	(destructor)Brute_dealloc, /*tp_dealloc*/
	0,                         /*tp_print*/
	0,                         /*tp_getattr*/
	0,                         /*tp_setattr*/
	0,			   /*tp_reserved*/
	0,                         /*tp_repr*/
	0,                         /*tp_as_number*/
	0,                         /*tp_as_sequence*/
	0,                         /*tp_as_mapping*/
	0,                         /*tp_hash */
	0,                         /*tp_call*/
	0,                         /*tp_str*/
	0,                         /*tp_getattro*/
	0,                         /*tp_setattro*/
	0,                         /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	0,           /* tp_doc */
	0,		               /* tp_traverse */
	0,		               /* tp_clear */
	0,		               /* tp_richcompare */
	0,		               /* tp_weaklistoffset */
	0,		               /* tp_iter */
	0,		               /* tp_iternext */
	Brute_methods,             /* tp_methods */
	0,             /* tp_members */
	0,                         /* tp_getset */
	0,                         /* tp_base */
	0,                         /* tp_dict */
	0,                         /* tp_descr_get */
	0,                         /* tp_descr_set */
	0,                         /* tp_dictoffset */
	(initproc)Brute_init,      /* tp_init */
	0,                         /* tp_alloc */
	Brute_new,                 /* tp_new */
};

/*************************************************************
		Module setup
*************************************************************/

PyMethodDef brutus_methods[] = {
	{NULL, NULL, 0, NULL}
};

PyModuleDef brutus_module = {
	PyModuleDef_HEAD_INIT,
	"brutus",
	"brutus",
	-1,
	brutus_methods
};

PyMODINIT_FUNC
PyInit_brutus(void) 
{
	PyObject* m;

	if (PyType_Ready(&BruteType) < 0)
		return NULL;

	m = PyModule_Create(&brutus_module);

	if (m == NULL)
		return NULL;

	Py_INCREF(&BruteType);
	PyModule_AddObject(m, "Brute", (PyObject *)&BruteType);
	return m;
}
