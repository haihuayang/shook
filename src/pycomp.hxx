
#ifndef __pycomp__h__
#define __pycomp__h__

#ifdef __cplusplus
extern "C" {
#endif

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K 1
#endif

#ifdef IS_PY3K
#define Py_TPFLAGS_HAVE_ITER 0
#define Py_TPFLAGS_CHECKTYPES 0

#define PyInt_Check PyLong_Check
#define PyInt_FromLong PyLong_FromLong
#define PyInt_FromSsize_t PyLong_FromSsize_t
#define PyInt_AsLong PyLong_AsLong
#define PyInt_AsSsize_t PyLong_AsSsize_t

#define PyString_FromString PyUnicode_FromString
#define PyString_Decode PyUnicode_Decode
#define PyString_FromFormat PyUnicode_FromFormat
#define PyString_Check PyUnicode_Check
#define PyString_AsString PyUnicode_AsUTF8
#define PyString_AsStringAndSize PyBytes_AsStringAndSize
#endif

#if 0
#if 0
static inline PyObject *py_init_module(const char *name, PyMethodDef *methods, const char *doc)
{
	static struct PyModuleDef moduledef = { PyModuleDef_HEAD_INIT, name, doc, -1, methods, };
	return PyModule_Create(&moduledef);
}

void pysys_set_argv(int argc, char **argv, int updatepath);

#define pystring_as_string	PyUnicode_AsUTF8 
#define pystring_from_string	PyUnicode_FromString 
#define pyint_check		PyLong_Check
#define pyint_as_long		PyLong_AsLong
#define pyint_from_long		PyLong_FromLong
#define pybytes_as_stringandsize	PyBytes_AsStringAndSize
#else
static inline PyObject *py_init_module(const char *name, PyMethodDef *methods, const char *doc)
{
	return Py_InitModule3(name, methods, doc);
}

#define pysys_set_argv		PySys_SetArgvEx
#define pystring_as_string	PyString_AsString 
#define pystring_from_string	PyString_FromString 
#define pyint_check		PyInt_Check
#define pyint_as_long		PyInt_AsLong
#define pyint_from_long		PyInt_FromLong
#define pybytes_as_stringandsize	PyString_AsStringAndSize
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __pycomp__h__ */

