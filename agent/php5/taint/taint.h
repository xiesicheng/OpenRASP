#pragma once

#include "openrasp.h"
#include "node_sequence.h"

using taint::NodeSequence;

#define OPENRASP_TAINT_MAGIC_LENGTH sizeof(unsigned)
#define OPENRASP_TAINT_MAGIC_NONE 0x00000000
#define OPENRASP_TAINT_MAGIC_POSSIBLE 0x6A8FCE84
#define OPENRASP_TAINT_MAGIC_UNTAINT 0x2C5E7F2D
#define OPENRASP_TAINT_POINTER_LENGTH sizeof(uintptr_t)
#define OPENRASP_TAINT_SUFFIX_LENGTH (OPENRASP_TAINT_POINTER_LENGTH + OPENRASP_TAINT_MAGIC_LENGTH)

#ifndef MAKE_REAL_ZVAL_PTR
#define MAKE_REAL_ZVAL_PTR(val)       \
    do                                \
    {                                 \
        zval *_tmp;                   \
        ALLOC_ZVAL(_tmp);             \
        INIT_PZVAL_COPY(_tmp, (val)); \
        (val) = _tmp;                 \
    } while (0)
#endif

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
#define OPENRASP_OP1_TYPE(n) ((n)->op1.op_type)
#define OPENRASP_OP2_TYPE(n) ((n)->op2.op_type)
#define OPENRASP_OP1_NODE_PTR(n) (&(n)->op1)
#define OPENRASP_OP2_NODE_PTR(n) (&(n)->op2)
#define OPENRASP_OP1_VAR(n) ((n)->op1.u.var)
#define OPENRASP_OP2_VAR(n) ((n)->op2.u.var)
#define OPENRASP_RESULT_VAR(n) ((n)->result.u.var)
#define OPENRASP_OP1_CONSTANT_PTR(n) (&(n)->op1.u.constant)
#define OPENRASP_OP2_CONSTANT_PTR(n) (&(n)->op2.u.constant)
#define OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(t) (execute_data->Ts)
#define OPENRASP_RETURN_VALUE_USED(n) (!((&(n)->result)->u.EA.type & EXT_TYPE_UNUSED))
#define OPENRASP_OP_LINENUM(n) ((n).u.opline_num)
#define OPENRASP_AI_SET_PTR(ai, val) \
    (ai).ptr = (val);                \
    (ai).ptr_ptr = &((ai).ptr);
#else
#define OPENRASP_OP1_TYPE(n) ((n)->op1_type)
#define OPENRASP_OP2_TYPE(n) ((n)->op2_type)
#define OPENRASP_OP1_NODE_PTR(n) ((n)->op1.var)
#define OPENRASP_OP2_NODE_PTR(n) ((n)->op2.var)
#define OPENRASP_OP1_VAR(n) ((n)->op1.var)
#define OPENRASP_OP2_VAR(n) ((n)->op2.var)
#define OPENRASP_RESULT_VAR(n) ((n)->result.var)
#define OPENRASP_OP1_CONSTANT_PTR(n) ((n)->op1.zv)
#define OPENRASP_OP2_CONSTANT_PTR(n) ((n)->op2.zv)
#define OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(t) (t)
#define OPENRASP_RETURN_VALUE_USED(n) (!((n)->result_type & EXT_TYPE_UNUSED))
#define OPENRASP_OP_LINENUM(n) ((n).opline_num)
#define OPENRASP_AI_SET_PTR(t, val)       \
    do                                    \
    {                                     \
        temp_variable *__t = (t);         \
        __t->var.ptr = (val);             \
        __t->var.ptr_ptr = &__t->var.ptr; \
    } while (0)
#endif

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
#define OPENRASP_T(offset) (*EX_TMP_VAR(execute_data, offset))
#define OPENRASP_CV(i) (*EX_CV_NUM(execute_data, i))
#define OPENRASP_CV_OF(i) (*EX_CV_NUM(EG(current_execute_data), i))
#define OPENRASP_PZVAL_LOCK(z) Z_ADDREF_P((z))
#else
#define OPENRASP_T(offset) (*(temp_variable *)((char *)execute_data->Ts + offset))
#define OPENRASP_CV(i) (EG(current_execute_data)->CVs[i])
#define OPENRASP_CV_OF(i) (EG(current_execute_data)->CVs[i])
#define OPENRASP_PZVAL_LOCK(z, f) taint_pzval_lock_func(z, f);
#endif

#define OPENRASP_TS(offset) (*(temp_variable *)((char *)Ts + offset))
#define OPENRASP_PZVAL_UNLOCK(z, f) openrasp_pzval_unlock_func(z, f, 1)
#define OPENRASP_PZVAL_UNLOCK_FREE(z) openrasp_pzval_unlock_free_func(z)
#define OPENRASP_CV_DEF_OF(i) (EG(active_op_array)->vars[i])
#define OPENRASP_TMP_FREE(z) (zval *)(((zend_uintptr_t)(z)) | 1L)

#define OPENRASP_AI_USE_PTR(ai)     \
    if ((ai).ptr_ptr)               \
    {                               \
        (ai).ptr = *((ai).ptr_ptr); \
        (ai).ptr_ptr = &((ai).ptr); \
    }                               \
    else                            \
    {                               \
        (ai).ptr = NULL;            \
    }

#define OPENRASP_AI_SET_PTR(t, val)       \
    do                                    \
    {                                     \
        temp_variable *__t = (t);         \
        __t->var.ptr = (val);             \
        __t->var.ptr_ptr = &__t->var.ptr; \
    } while (0)

#define OPENRASP_FREE_OP(should_free)                                   \
    if (should_free.var)                                                \
    {                                                                   \
        if ((zend_uintptr_t)should_free.var & 1L)                       \
        {                                                               \
            zval_dtor((zval *)((zend_uintptr_t)should_free.var & ~1L)); \
        }                                                               \
        else                                                            \
        {                                                               \
            zval_ptr_dtor(&should_free.var);                            \
        }                                                               \
    }
#define OPENRASP_FREE_OP_VAR_PTR(should_free) \
    if (should_free.var)                      \
    {                                         \
        zval_ptr_dtor(&should_free.var);      \
    }

#define OPENRASP_TAINT_MARK(zv, ptr)                                                                                            \
    do                                                                                                                          \
    {                                                                                                                           \
        *((NodeSequence **)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) = (ptr);                                                      \
        *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + OPENRASP_TAINT_POINTER_LENGTH + 1)) = (OPENRASP_TAINT_MAGIC_POSSIBLE); \
        OPENRASP_G(sequenceManager).registerSequence(ptr);                                                                      \
    } while (0)

#define OPENRASP_TAINT_POSSIBLE(zv) (Z_TYPE_P(zv) == IS_STRING && Z_STRLEN_P(zv) && *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + OPENRASP_TAINT_POINTER_LENGTH + 1)) == OPENRASP_TAINT_MAGIC_POSSIBLE)
#define OPENRASP_TAINT_SEQUENCE(zv) (OPENRASP_TAINT_POSSIBLE(zv) ? **((NodeSequence **)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) : NodeSequence(Z_TYPE_P(zv) == IS_STRING ? Z_STRLEN_P(zv) : 0))

typedef struct _openrasp_free_op
{
    zval *var;
    int is_ref;
    int type;
} openrasp_free_op;

void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource TSRMLS_DC);
int openrasp_concat_handler(ZEND_OPCODE_HANDLER_ARGS);
int openrasp_assign_concat_handler(ZEND_OPCODE_HANDLER_ARGS);
int openrasp_add_char_handler(ZEND_OPCODE_HANDLER_ARGS);
int openrasp_assign_handler(ZEND_OPCODE_HANDLER_ARGS);
int openrasp_add_var_handler(ZEND_OPCODE_HANDLER_ARGS);