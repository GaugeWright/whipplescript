/* Feasibility fixture: host-owned expectations, native CPython return values.
 * Experimental ABI; artifact packaging and production integration remain open. */
#include <Python.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include "norm-frozen-stdlib.h"

static PyObject *candidate;

uint32_t norm_python_version(void) { return PY_VERSION_HEX; }

int norm_init(void) {
    PyImport_FrozenModules = norm_frozen_modules;
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.install_signal_handlers = 0;
    config.use_frozen_modules = 1;
    config.module_search_paths_set = 1;
    PyStatus status = PyWideStringList_Append(&config.module_search_paths, L"/Lib");
    if (PyStatus_Exception(status)) { PyConfig_Clear(&config); return -1; }
    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    return PyStatus_Exception(status) ? -1 : 0;
}

int norm_load(const char *source) {
    PyObject *module = PyImport_AddModule("norm_candidate");
    if (!module) return -1;
    PyObject *globals = PyModule_GetDict(module);
    PyObject *value = PyRun_String(source, Py_file_input, globals, globals);
    if (!value) { PyErr_Clear(); return -1; }
    Py_DECREF(value);
    candidate = PyObject_GetAttrString(module, "authorize");
    if (!candidate || !PyCallable_Check(candidate)) { PyErr_Clear(); return -1; }
    return 0;
}

int norm_call(const char *role, const char *grant) {
    if (!candidate) return -1;
    PyObject *result = PyObject_CallFunction(candidate, "ss", role, grant);
    if (!result) { PyErr_Clear(); return -1; }
    int answer = result == Py_True ? 1 : result == Py_False ? 0 : -2;
    Py_DECREF(result);
    return answer;
}

/* Structured-return feasibility ABI. All traversal uses native payload APIs;
 * no Python iteration, __str__, __float__, or JSON serialization callbacks. */
#include <math.h>
#include <stdio.h>
#include <string.h>
#define RESULT_CAPACITY (2 * 1024 * 1024)
#define STRING_BUDGET (256 * 1024)
static char result_bytes[RESULT_CAPACITY];
static size_t result_size;
static size_t strings_left;
static size_t nodes_left;
static int result_error;

static int append_bytes(const char *bytes, size_t size) {
    if (size > RESULT_CAPACITY - result_size) { result_error = -7; return 0; }
    memcpy(result_bytes + result_size, bytes, size);
    result_size += size;
    return 1;
}
static int append_literal(const char *text) { return append_bytes(text, strlen(text)); }
static int encode_string(PyObject *value) {
    Py_ssize_t size;
    const char *bytes = PyUnicode_AsUTF8AndSize(value, &size);
    if (!bytes) { PyErr_Clear(); result_error = -2; return 0; }
    if ((size_t)size > strings_left) { result_error = -4; return 0; }
    strings_left -= (size_t)size;
    if (!append_literal("\"")) return 0;
    for (Py_ssize_t i = 0; i < size; ++i) {
        unsigned char byte = (unsigned char)bytes[i];
        if (byte == '"' || byte == '\\') {
            char escaped[] = {'\\', (char)byte};
            if (!append_bytes(escaped, 2)) return 0;
        } else if (byte < 32) {
            char escaped[7];
            snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
            if (!append_bytes(escaped, 6)) return 0;
        } else if (!append_bytes(bytes + i, 1)) return 0;
    }
    return append_literal("\"");
}
static int encode_value(PyObject *value, unsigned depth) {
    if (depth > 32) { result_error = -5; return 0; }
    if (nodes_left == 0) { result_error = -6; return 0; }
    --nodes_left;
    if (value == Py_None) return append_literal("null");
    if (value == Py_True) return append_literal("true");
    if (value == Py_False) return append_literal("false");
    if (PyUnicode_Check(value)) return encode_string(value);
    if (PyLong_Check(value)) {
        char text[32];
        int overflow = 0;
        long long integer = PyLong_AsLongLongAndOverflow(value, &overflow);
        if (PyErr_Occurred()) { PyErr_Clear(); result_error = -2; return 0; }
        if (overflow) {
            unsigned long long unsigned_integer = PyLong_AsUnsignedLongLong(value);
            if (PyErr_Occurred()) { PyErr_Clear(); result_error = -2; return 0; }
            snprintf(text, sizeof(text), "%llu", unsigned_integer);
        } else snprintf(text, sizeof(text), "%lld", integer);
        return append_literal(text);
    }
    if (PyFloat_Check(value)) {
        double number = PyFloat_AS_DOUBLE(value);
        if (!isfinite(number)) { result_error = -3; return 0; }
        char *text = PyOS_double_to_string(number, 'r', 0, Py_DTSF_ADD_DOT_0, NULL);
        if (!text) { PyErr_Clear(); result_error = -2; return 0; }
        int ok = append_literal(text);
        PyMem_Free(text);
        return ok;
    }
    if (PyList_Check(value) || PyTuple_Check(value)) {
        int is_list = PyList_Check(value);
        Py_ssize_t count = is_list ? PyList_GET_SIZE(value) : PyTuple_GET_SIZE(value);
        if ((size_t)count > nodes_left) { result_error = -6; return 0; }
        if (!append_literal("[")) return 0;
        for (Py_ssize_t i = 0; i < count; ++i) {
            if (i && !append_literal(",")) return 0;
            PyObject *item = is_list ? PyList_GET_ITEM(value, i) : PyTuple_GET_ITEM(value, i);
            if (!encode_value(item, depth + 1)) return 0;
        }
        return append_literal("]");
    }
    if (PyDict_Check(value)) {
        if ((size_t)PyDict_Size(value) > nodes_left) { result_error = -6; return 0; }
        Py_ssize_t position = 0;
        PyObject *key, *item;
        int first = 1;
        if (!append_literal("{")) return 0;
        while (PyDict_Next(value, &position, &key, &item)) {
            if (!PyUnicode_Check(key)) { result_error = -2; return 0; }
            if (!first && !append_literal(",")) return 0;
            first = 0;
            if (!encode_string(key) || !append_literal(":") || !encode_value(item, depth + 1)) return 0;
        }
        return append_literal("}");
    }
    result_error = -2;
    return 0;
}

int norm_call_json(const char *role, const char *grant) {
    result_size = 0;
    strings_left = STRING_BUDGET;
    nodes_left = 10000;
    result_error = 0;
    if (!candidate) return -1;
    PyObject *result = PyObject_CallFunction(candidate, "ss", role, grant);
    if (!result) { PyErr_Clear(); return -1; }
    int ok = encode_value(result, 0);
    /* Destructors can execute guest code on DECREF. The host still treats any
     * trap here as failure and never consumes a partial serialization. */
    Py_DECREF(result);
    if (!ok) { result_size = 0; return result_error ? result_error : -2; }
    return 0;
}
uintptr_t norm_result_ptr(void) { return (uintptr_t)result_bytes; }
size_t norm_result_len(void) { return result_size; }

/* Host-only constructors. Returned handles own one reference. Container
 * insertion retains a reference, so the host drops each temporary afterward. */
uintptr_t norm_new_none(void) { return (uintptr_t)Py_NewRef(Py_None); }
uintptr_t norm_new_bool(int value) { return (uintptr_t)PyBool_FromLong(value != 0); }
uintptr_t norm_new_string(const char *value, size_t size) {
    PyObject *result = PyUnicode_DecodeUTF8(value, (Py_ssize_t)size, "strict");
    if (!result) PyErr_Clear();
    return (uintptr_t)result;
}
uintptr_t norm_new_integer(const char *value) {
    char *end;
    PyObject *result = PyLong_FromString(value, &end, 10);
    if (!result || *end != '\0') { Py_XDECREF(result); PyErr_Clear(); return 0; }
    return (uintptr_t)result;
}
uintptr_t norm_new_float(double value) {
    if (!isfinite(value)) return 0;
    return (uintptr_t)PyFloat_FromDouble(value);
}
uintptr_t norm_new_list(void) { return (uintptr_t)PyList_New(0); }
uintptr_t norm_new_dict(void) { return (uintptr_t)PyDict_New(); }
int norm_list_push(uintptr_t container, uintptr_t item) {
    if (!container || !item || !PyList_CheckExact((PyObject *)container)) return -1;
    int status = PyList_Append((PyObject *)container, (PyObject *)item);
    if (status < 0) PyErr_Clear();
    return status;
}
int norm_dict_set(uintptr_t container, uintptr_t key, uintptr_t item) {
    if (!container || !key || !item || !PyDict_CheckExact((PyObject *)container)
        || !PyUnicode_CheckExact((PyObject *)key)) return -1;
    int status = PyDict_SetItem((PyObject *)container, (PyObject *)key, (PyObject *)item);
    if (status < 0) PyErr_Clear();
    return status;
}
void norm_drop(uintptr_t value) { Py_XDECREF((PyObject *)value); }
int norm_call_values(uintptr_t args, uintptr_t kwargs) {
    result_size = 0;
    strings_left = STRING_BUDGET;
    nodes_left = 10000;
    result_error = 0;
    if (!candidate || !args || !kwargs || !PyList_CheckExact((PyObject *)args)
        || !PyDict_CheckExact((PyObject *)kwargs)) return -1;
    PyObject *tuple = PyList_AsTuple((PyObject *)args);
    if (!tuple) { PyErr_Clear(); return -1; }
    PyObject *result = PyObject_Call(candidate, tuple, (PyObject *)kwargs);
    Py_DECREF(tuple);
    if (!result) { PyErr_Clear(); return -1; }
    int ok = encode_value(result, 0);
    Py_DECREF(result);
    if (!ok) { result_size = 0; return result_error ? result_error : -2; }
    return 0;
}

/* Diagnostics go directly to the host-bounded WASI sink. No Python stream
 * or codec is called; no interpreter shutdown is needed to flush output. */
static PyObject *capture_diagnostic(PyObject *self, PyObject *value) {
    (void)self;
    if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "diagnostics require text");
        return NULL;
    }
    Py_ssize_t size;
    const char *bytes = PyUnicode_AsUTF8AndSize(value, &size);
    if (!bytes) return NULL;
    Py_ssize_t offset = 0;
    while (offset < size) {
        ssize_t written = write(1, bytes + offset, (size_t)(size - offset));
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return PyErr_SetFromErrno(PyExc_OSError);
        offset += written;
    }
    return PyLong_FromSsize_t(PyUnicode_GET_LENGTH(value));
}
static PyMethodDef diagnostic_method = {
    "capture_diagnostic", capture_diagnostic, METH_O, NULL
};

int norm_install_files(uintptr_t files, const char *loader_source) {
    if (!files || !PyDict_CheckExact((PyObject *)files)) return -1;
    PyObject *module = PyImport_AddModule("_norm_captured_loader");
    if (!module) { PyErr_Clear(); return -1; }
    PyObject *globals = PyModule_GetDict(module);
    PyObject *sink = PyCFunction_New(&diagnostic_method, NULL);
    if (!sink) { PyErr_Clear(); return -1; }
    int status = PyDict_SetItemString(globals, "captured_files", (PyObject *)files);
    if (status == 0) status = PyDict_SetItemString(globals, "capture_diagnostic", sink);
    Py_DECREF(sink);
    if (status < 0) { PyErr_Clear(); return -1; }
    PyObject *result;
    result = PyRun_String(loader_source, Py_file_input, globals, globals);
    if (!result) { PyErr_Clear(); return -1; }
    Py_DECREF(result);
    return 0;
}

int norm_select(const char *module_name, const char *function_name) {
    /* The host must also validate that the requested module is captured. A
     * cached runtime module is never accepted as a candidate entry point. */
    if (PyDict_GetItemString(PyImport_GetModuleDict(), module_name)) return -9;
    PyObject *module = PyImport_ImportModule(module_name);
    if (!module) { PyErr_Clear(); return -1; }
    PyObject *function = PyObject_GetAttrString(module, function_name);
    Py_DECREF(module);
    if (!function || !PyCallable_Check(function)) { Py_XDECREF(function); PyErr_Clear(); return -1; }
    Py_XDECREF(candidate);
    candidate = function;
    return 0;
}
