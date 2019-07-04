#include "openrasp_hook.h"
#include "taint.h"

extern "C"
{
#include "zend_compile.h"
#include "zend_execute.h"
#include "ext/standard/info.h"
}

using taint::TaintNode;

static void openrasp_pzval_unlock_func(zval *z, openrasp_free_op *should_free, int unref);
static void openrasp_pzval_unlock_free_func(zval *z);
static void openrasp_pzval_lock_func(zval *z, openrasp_free_op *should_free);
static int openrasp_binary_assign_op_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS);
static int openrasp_binary_assign_op_obj_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS);
static zval **openrasp_get_obj_zval_ptr_ptr_unused(TSRMLS_D);
static void make_real_object(zval **object_ptr TSRMLS_DC);
static zval **openrasp_fetch_dimension_address_inner(HashTable *ht, zval *dim, int dim_type, int type TSRMLS_DC);
static void openrasp_assign_to_variable_reference(zval **variable_ptr_ptr, zval **value_ptr_ptr TSRMLS_DC);

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
static void openrasp_fetch_dimension_address(temp_variable *result, zval **container_ptr, zval *dim, int dim_is_tmp_var, int type TSRMLS_DC);
#else
static void openrasp_fetch_dimension_address(temp_variable *result, zval **container_ptr, zval *dim, int dim_type, int type TSRMLS_DC);
#endif

//5.3-
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)

static inline zval *openrasp_get_zval_ptr_var(znode *node, temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    zval *ptr = OPENRASP_TS(node->u.var).var.ptr;
    if (ptr)
    {
        OPENRASP_PZVAL_UNLOCK(ptr, should_free);
        return ptr;
    }
    else
    {
        temp_variable *T = (temp_variable *)((char *)Ts + node->u.var);
        zval *str = T->str_offset.str;

        /* string offset */
        ALLOC_ZVAL(ptr);
        T->str_offset.ptr = ptr;
        should_free->var = ptr;

        if (T->str_offset.str->type != IS_STRING || ((int)T->str_offset.offset < 0) || (T->str_offset.str->value.str.len <= (int)T->str_offset.offset))
        {
            ptr->value.str.val = STR_EMPTY_ALLOC();
            ptr->value.str.len = 0;
        }
        else
        {
            char c = str->value.str.val[T->str_offset.offset];

            ptr->value.str.val = estrndup(&c, 1);
            ptr->value.str.len = 1;
        }
        OPENRASP_PZVAL_UNLOCK_FREE(str);

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3)
        ptr->refcount = 1;
        ptr->is_ref = 1;
#else
        ptr->refcount__gc = 1;
        ptr->is_ref__gc = 1;
#endif

        ptr->type = IS_STRING;
        return ptr;
    }
}

static zval *openrasp_get_zval_ptr_cv(znode *node, temp_variable *Ts TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(node->u.var);
    if (!*ptr)
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(node->u.var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
            return &EG(uninitialized_zval);
        }
    }
    return **ptr;
}

static zval *openrasp_get_zval_ptr_tmp(znode *node, temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    return should_free->var = &OPENRASP_TS(node->u.var).tmp_var;
}

static zval **openrasp_get_zval_ptr_ptr_var(znode *node, temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    zval **ptr_ptr = OPENRASP_TS(node->u.var).var.ptr_ptr;

    if (ptr_ptr)
    {
        OPENRASP_PZVAL_UNLOCK(*ptr_ptr, should_free);
    }
    else
    {
        /* string offset */
        OPENRASP_PZVAL_UNLOCK(OPENRASP_TS(node->u.var).str_offset.str, should_free);
    }
    return ptr_ptr;
}

static zval **openrasp_get_zval_ptr_ptr_cv(znode *node, temp_variable *Ts, int type TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(node->u.var);

    if (!*ptr)
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(node->u.var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            switch (type)
            {
            case BP_VAR_R:
            case BP_VAR_UNSET:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_IS:
                return &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_W:
                openrasp_get_cv_address(cv, ptr, Ts TSRMLS_CC);
                break;
            }
        }
    }
    return *ptr;
}

static zval **openrasp_get_zval_ptr_ptr(znode *node, temp_variable *Ts, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    should_free->type = node->op_type;
    if (node->op_type == IS_CV)
    {
        should_free->var = 0;
        return openrasp_get_zval_ptr_ptr_cv(node, Ts, type TSRMLS_CC);
    }
    else if (node->op_type == IS_VAR)
    {
        return openrasp_get_zval_ptr_ptr_var(node, Ts, should_free TSRMLS_CC);
    }
    else
    {
        should_free->var = 0;
        return NULL;
    }
}

static zval *openrasp_get_zval_ptr(znode *node, temp_variable *Ts, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    /*	should_free->is_var = 0; */
    switch (node->op_type)
    {
    case IS_CONST:
        should_free->var = 0;
        return &node->u.constant;
        break;
    case IS_TMP_VAR:
        should_free->var = OPENRASP_TMP_FREE(&OPENRASP_TS(node->u.var).tmp_var);
        return &OPENRASP_TS(node->u.var).tmp_var;
        break;
    case IS_VAR:
        return openrasp_get_zval_ptr_var(node, Ts, should_free TSRMLS_CC);
        break;
    case IS_UNUSED:
        should_free->var = 0;
        return NULL;
        break;
    case IS_CV:
        should_free->var = 0;
        return openrasp_get_zval_ptr_cv(node, Ts TSRMLS_CC);
        break;
        EMPTY_SWITCH_DEFAULT_CASE()
    }
    return NULL;
}

//php5.5
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)

static zval *openrasp_get_zval_ptr_var(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    zval *ptr = OPENRASP_T(var).var.ptr;
    OPENRASP_PZVAL_UNLOCK(ptr, should_free);
    return ptr;
}

static zval *openrasp_get_zval_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = EX_CV_NUM(EG(current_execute_data), var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
            return &EG(uninitialized_zval);
        }
    }
    return **ptr;
}

static zval *openrasp_get_zval_ptr_tmp(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    return should_free->var = &OPENRASP_T(var).tmp_var;
}

static zval **openrasp_get_zval_ptr_ptr_var(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    zval **ptr_ptr = OPENRASP_T(var).var.ptr_ptr;

    if (EXPECTED(ptr_ptr != NULL))
    {
        OPENRASP_PZVAL_UNLOCK(*ptr_ptr, should_free);
    }
    else
    {
        /* string offset */
        OPENRASP_PZVAL_UNLOCK(OPENRASP_T(var).str_offset.str, should_free);
    }
    return ptr_ptr;
}

static zval **openrasp_get_zval_ptr_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            switch (type)
            {
            case BP_VAR_R:
            case BP_VAR_UNSET:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_IS:
                return &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_W:
                Z_ADDREF(EG(uninitialized_zval));
                if (!EG(active_symbol_table))
                {
                    *ptr = (zval **)EX_CV_NUM(EG(current_execute_data), EG(active_op_array)->last_var + var);
                    **ptr = &EG(uninitialized_zval);
                }
                else
                {
                    zend_hash_quick_update(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, &EG(uninitialized_zval_ptr), sizeof(zval *), (void **)ptr);
                }
                break;
            }
        }
    }
    return *ptr;
}

static zval **openrasp_get_zval_ptr_ptr(int op_type, const znode_op *node, const zend_execute_data *execute_data, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    should_free->type = op_type;
    if (op_type == IS_CV)
    {
        should_free->var = 0;
        return openrasp_get_zval_ptr_ptr_cv(node->var, type TSRMLS_CC);
    }
    else if (op_type == IS_VAR)
    {
        return openrasp_get_zval_ptr_ptr_var(node->var, execute_data, should_free TSRMLS_CC);
    }
    else
    {
        should_free->var = 0;
        return NULL;
    }
}

static zval *openrasp_get_zval_ptr(int op_type, const znode_op *node, const zend_execute_data *execute_data, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    /*	should_free->is_var = 0; */
    switch (op_type)
    {
    case IS_CONST:
        should_free->var = 0;
        return node->zv;
        break;
    case IS_TMP_VAR:
        should_free->var = OPENRASP_TMP_FREE(&OPENRASP_T(node->var).tmp_var);
        return &OPENRASP_T(node->var).tmp_var;
        break;
    case IS_VAR:
        return openrasp_get_zval_ptr_var(node->var, execute_data, should_free TSRMLS_CC);
        break;
    case IS_UNUSED:
        should_free->var = 0;
        return NULL;
        break;
    case IS_CV:
        should_free->var = 0;
        return openrasp_get_zval_ptr_cv(node->var, type TSRMLS_CC);
        break;
        EMPTY_SWITCH_DEFAULT_CASE()
    }
    return NULL;
}

//php5.6
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 6)

static zval *openrasp_get_zval_ptr_var(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    zval *ptr = OPENRASP_T(var).var.ptr;
    return should_free->var = ptr;
}

static zval *openrasp_get_zval_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = EX_CV_NUM(EG(current_execute_data), var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
            return &EG(uninitialized_zval);
        }
    }
    return **ptr;
}

static zval *openrasp_get_zval_ptr_tmp(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    return should_free->var = &OPENRASP_T(var).tmp_var;
}

static zval **openrasp_get_zval_ptr_ptr_var(zend_uint var, const zend_execute_data *execute_data, openrasp_free_op *should_free TSRMLS_DC)
{
    zval **ptr_ptr = OPENRASP_T(var).var.ptr_ptr;

    if (EXPECTED(ptr_ptr != NULL))
    {
        OPENRASP_PZVAL_UNLOCK(*ptr_ptr, should_free);
    }
    else
    {
        /* string offset */
        OPENRASP_PZVAL_UNLOCK(OPENRASP_T(var).str_offset.str, should_free);
    }
    return ptr_ptr;
}

static zval **openrasp_get_zval_ptr_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            switch (type)
            {
            case BP_VAR_R:
            case BP_VAR_UNSET:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_IS:
                return &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_W:
                Z_ADDREF(EG(uninitialized_zval));
                if (!EG(active_symbol_table))
                {
                    *ptr = (zval **)EX_CV_NUM(EG(current_execute_data), EG(active_op_array)->last_var + var);
                    **ptr = &EG(uninitialized_zval);
                }
                else
                {
                    zend_hash_quick_update(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, &EG(uninitialized_zval_ptr), sizeof(zval *), (void **)ptr);
                }
                break;
            }
        }
    }
    return *ptr;
}

static zval **openrasp_get_zval_ptr_ptr(int op_type, const znode_op *node, const zend_execute_data *execute_data, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    should_free->type = op_type;
    if (op_type == IS_CV)
    {
        should_free->var = 0;
        return openrasp_get_zval_ptr_ptr_cv(node->var, type TSRMLS_CC);
    }
    else if (op_type == IS_VAR)
    {
        return openrasp_get_zval_ptr_ptr_var(node->var, execute_data, should_free TSRMLS_CC);
    }
    else
    {
        should_free->var = 0;
        return NULL;
    }
}

static zval *openrasp_get_zval_ptr(int op_type, const znode_op *node, const zend_execute_data *execute_data, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    /*	should_free->is_var = 0; */
    switch (op_type)
    {
    case IS_CONST:
        should_free->var = 0;
        return node->zv;
        break;
    case IS_TMP_VAR:
        should_free->var = OPENRASP_TMP_FREE(&OPENRASP_T(node->var).tmp_var);
        return &OPENRASP_T(node->var).tmp_var;
        break;
    case IS_VAR:
        return openrasp_get_zval_ptr_var(node->var, execute_data, should_free TSRMLS_CC);
        break;
    case IS_UNUSED:
        should_free->var = 0;
        return NULL;
        break;
    case IS_CV:
        should_free->var = 0;
        return openrasp_get_zval_ptr_cv(node->var, type TSRMLS_CC);
        break;
        EMPTY_SWITCH_DEFAULT_CASE()
    }
    return NULL;
}

#else

static zval *openrasp_get_zval_ptr_var(zend_uint var, const temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    zval *ptr = OPENRASP_TS(var).var.ptr;
    OPENRASP_PZVAL_UNLOCK(ptr, should_free);
    return ptr;
}

static zval *openrasp_get_zval_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
            return &EG(uninitialized_zval);
        }
    }
    return **ptr;
}

static zval *openrasp_get_zval_ptr_tmp(zend_uint var, const temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    return should_free->var = &OPENRASP_TS(var).tmp_var;
}

static zval **openrasp_get_zval_ptr_ptr_var(zend_uint var, const temp_variable *Ts, openrasp_free_op *should_free TSRMLS_DC)
{
    zval **ptr_ptr = OPENRASP_TS(var).var.ptr_ptr;

    if (EXPECTED(ptr_ptr != NULL))
    {
        OPENRASP_PZVAL_UNLOCK(*ptr_ptr, should_free);
    }
    else
    {
        /* string offset */
        OPENRASP_PZVAL_UNLOCK(OPENRASP_TS(var).str_offset.str, should_free);
    }
    return ptr_ptr;
}

static zval **openrasp_get_zval_ptr_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
    zval ***ptr = &OPENRASP_CV_OF(var);

    if (UNEXPECTED(*ptr == NULL))
    {
        zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(var);
        if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE)
        {
            switch (type)
            {
            case BP_VAR_R:
            case BP_VAR_UNSET:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_IS:
                return &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
                /* break missing intentionally */
            case BP_VAR_W:
                Z_ADDREF(EG(uninitialized_zval));
                if (!EG(active_symbol_table))
                {
                    *ptr = (zval **)EG(current_execute_data)->CVs + (EG(active_op_array)->last_var + var);
                    **ptr = &EG(uninitialized_zval);
                }
                else
                {
                    zend_hash_quick_update(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, &EG(uninitialized_zval_ptr), sizeof(zval *), (void **)ptr);
                }
                break;
            }
        }
    }
    return *ptr;
}

static zval **openrasp_get_zval_ptr_ptr(int op_type, const znode_op *node, const temp_variable *Ts, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    should_free->type = op_type;
    if (op_type == IS_CV)
    {
        should_free->var = 0;
        return openrasp_get_zval_ptr_ptr_cv(node->var, type TSRMLS_CC);
    }
    else if (op_type == IS_VAR)
    {
        return openrasp_get_zval_ptr_ptr_var(node->var, Ts, should_free TSRMLS_CC);
    }
    else
    {
        should_free->var = 0;
        return NULL;
    }
}

static zval *openrasp_get_zval_ptr(int op_type, const znode_op *node, const temp_variable *Ts, openrasp_free_op *should_free, int type TSRMLS_DC)
{
    /*	should_free->is_var = 0; */
    switch (op_type)
    {
    case IS_CONST:
        should_free->var = 0;
        return node->zv;
        break;
    case IS_TMP_VAR:
        should_free->var = OPENRASP_TMP_FREE(&OPENRASP_TS(node->var).tmp_var);
        return &OPENRASP_TS(node->var).tmp_var;
        break;
    case IS_VAR:
        return openrasp_get_zval_ptr_var(node->var, Ts, should_free TSRMLS_CC);
        break;
    case IS_UNUSED:
        should_free->var = 0;
        return NULL;
        break;
    case IS_CV:
        should_free->var = 0;
        return openrasp_get_zval_ptr_cv(node->var, type TSRMLS_CC);
        break;
        EMPTY_SWITCH_DEFAULT_CASE()
    }
    return NULL;
}

#endif

//OPCODE ZEND_CONCAT https://www.php.net/manual/zh/internals2.opcodes.concat.php
int openrasp_concat_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL, *op2 = NULL, *result;
    openrasp_free_op free_op1 = {0}, free_op2 = {0};

    result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;
    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;

    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;

    case IS_CV:
        op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;

    case IS_CONST:
        op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
        break;
    }

    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;

    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op2 = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        op2 = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;

    case IS_CV:
        op2 = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;

    case IS_CONST:
        op2 = OPENRASP_OP2_CONSTANT_PTR(opline);
        break;
    }

    bool is_op1_tainted_string = op1 && IS_STRING == Z_TYPE_P(op1) && OPENRASP_TAINT_POSSIBLE(op1);
    bool is_op2_tainted_string = op2 && IS_STRING == Z_TYPE_P(op2) && OPENRASP_TAINT_POSSIBLE(op2);
    NodeSequence ns;
    if (is_op1_tainted_string || is_op2_tainted_string)
    {
        ns.append(OPENRASP_TAINT_SEQUENCE(op1));
        ns.append(OPENRASP_TAINT_SEQUENCE(op2));
    }

    concat_function(result, op1, op2 TSRMLS_CC);
    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result) && ns.length() == Z_STRLEN_P(result))
    {
        Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(result, new NodeSequence(ns));
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op1.var);
        break;
    case IS_VAR:
        if (free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        }
        break;
    }

    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op2.var);
        break;
    case IS_VAR:
        if (free_op2.var)
        {
            zval_ptr_dtor(&free_op2.var);
        }
        break;
    }

    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_assign_concat_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    return openrasp_binary_assign_op_helper(concat_function, ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
}

static zval **openrasp_get_obj_zval_ptr_ptr_unused(TSRMLS_D)
{
    if (EG(This))
    {
        return &EG(This);
    }
    else
    {
        zend_error(E_ERROR, "Using $this when not in object context");
        return NULL;
    }
}

static void make_real_object(zval **object_ptr TSRMLS_DC)
{
    if (Z_TYPE_PP(object_ptr) == IS_NULL ||
        (Z_TYPE_PP(object_ptr) == IS_BOOL && Z_LVAL_PP(object_ptr) == 0) ||
        (Z_TYPE_PP(object_ptr) == IS_STRING && Z_STRLEN_PP(object_ptr) == 0))
    {
        zend_error(E_STRICT, "Creating default object from empty value");
        SEPARATE_ZVAL_IF_NOT_REF(object_ptr);
        zval_dtor(*object_ptr);
        object_init(*object_ptr);
    }
}

static int openrasp_binary_assign_op_obj_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zend_op *op_data = opline + 1;
    openrasp_free_op free_op1 = {0}, free_op2 = {0}, free_op_data1 = {0};
    zval **object_ptr = NULL, *object = NULL, *property = NULL;
    int have_get_ptr = 0;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
    zval *value = openrasp_get_zval_ptr(&op_data->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
    zval *value = openrasp_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data, &free_op_data1, BP_VAR_R TSRMLS_CC);
#else
    zval *value = openrasp_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
#endif
    zval **retval = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr;

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        object_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        object_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        if (!object_ptr)
        {
            zend_error(E_ERROR, "Cannot use string offset as an object");
            return 0;
        }
        break;
    case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
        object_ptr = openrasp_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_W TSRMLS_CC);
#else
        object_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W TSRMLS_CC);
#endif
        break;
    case IS_UNUSED:
        object_ptr = openrasp_get_obj_zval_ptr_ptr_unused(TSRMLS_C);
        break;
    default:
        /* do nothing */
        break;
    }

    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        property = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        property = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;
    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        property = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        property = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        property = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;
    case IS_CONST:
        property = OPENRASP_OP2_CONSTANT_PTR(opline);
        break;
    case IS_UNUSED:
        property = NULL;
        break;
    default:
        /* do nothing */
        break;
    }

    OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr = NULL;
    make_real_object(object_ptr TSRMLS_CC);
    object = *object_ptr;

    if (Z_TYPE_P(object) != IS_OBJECT)
    {
        zend_error(E_WARNING, "Attempt to assign property of non-object");
        switch (OPENRASP_OP2_TYPE(opline))
        {
        case IS_TMP_VAR:
            zval_dtor(free_op2.var);
            break;
        case IS_VAR:
            if (free_op2.var)
            {
                zval_ptr_dtor(&free_op2.var);
            };
            break;
        case IS_CV:
        case IS_CONST:
        case IS_UNUSED:
        default:
            /* do nothing */
            break;
        }
        OPENRASP_FREE_OP(free_op_data1);

        if (OPENRASP_RETURN_VALUE_USED(opline))
        {
            *retval = EG(uninitialized_zval_ptr);
            Z_ADDREF_P(*retval);
        }
    }
    else
    {
        /* here we are sure we are dealing with an object */
        if (IS_TMP_VAR == OPENRASP_OP2_TYPE(opline))
        {
            MAKE_REAL_ZVAL_PTR(property);
        }

        /* here property is a string */
        if (opline->extended_value == ZEND_ASSIGN_OBJ && Z_OBJ_HT_P(object)->get_property_ptr_ptr)
        {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property TSRMLS_CC);
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property, BP_VAR_RW, ((OPENRASP_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL) TSRMLS_CC);
#else
            zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property, ((IS_CONST == IS_CONST) ? opline->op2.literal : NULL) TSRMLS_CC);
#endif
            if (zptr != NULL)
            { /* NULL means no success in getting PTR */
                bool is_zptr_tainted_string = *zptr && IS_STRING == Z_TYPE_PP(zptr) && OPENRASP_TAINT_POSSIBLE(*zptr);
                bool is_value_tainted_string = value && IS_STRING == Z_TYPE_P(value) && OPENRASP_TAINT_POSSIBLE(value);
                NodeSequence ns_have_get_ptr;
                if (is_zptr_tainted_string || is_value_tainted_string)
                {
                    ns_have_get_ptr.append(OPENRASP_TAINT_SEQUENCE(*zptr));
                    ns_have_get_ptr.append(OPENRASP_TAINT_SEQUENCE(value));
                }

                SEPARATE_ZVAL_IF_NOT_REF(zptr);
                have_get_ptr = 1;

                binary_op(*zptr, *zptr, value TSRMLS_CC);
                if (ns_have_get_ptr.taintedSize() && IS_STRING == Z_TYPE_PP(zptr) && Z_STRLEN_PP(zptr) && ns_have_get_ptr.length() == Z_STRLEN_PP(zptr))
                {
                    Z_STRVAL_PP(zptr) = (char *)erealloc(Z_STRVAL_PP(zptr), Z_STRLEN_PP(zptr) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
                    OPENRASP_TAINT_MARK(*zptr, new NodeSequence(ns_have_get_ptr));
                }
                if (OPENRASP_RETURN_VALUE_USED(opline))
                {
                    *retval = *zptr;
                    Z_ADDREF_P(*retval);
                }
            }
        }

        if (!have_get_ptr)
        {
            zval *z = NULL;

            switch (opline->extended_value)
            {
            case ZEND_ASSIGN_OBJ:
                if (Z_OBJ_HT_P(object)->read_property)
                {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
                    z = Z_OBJ_HT_P(object)->read_property(object, property, BP_VAR_R TSRMLS_CC);
#else
                    z = Z_OBJ_HT_P(object)->read_property(object, property, BP_VAR_R, ((OPENRASP_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL) TSRMLS_CC);
#endif
                }
                break;
            case ZEND_ASSIGN_DIM:
                if (Z_OBJ_HT_P(object)->read_dimension)
                {
                    z = Z_OBJ_HT_P(object)->read_dimension(object, property, BP_VAR_R TSRMLS_CC);
                }
                break;
            }
            if (z)
            {
                if (Z_TYPE_P(z) == IS_OBJECT && Z_OBJ_HT_P(z)->get)
                {
                    zval *value = Z_OBJ_HT_P(z)->get(z TSRMLS_CC);

                    if (Z_REFCOUNT_P(z) == 0)
                    {
                        zval_dtor(z);
                        FREE_ZVAL(z);
                    }
                    z = value;
                }
                Z_ADDREF_P(z);
                bool is_z_tainted_string = z && IS_STRING == Z_TYPE_P(z) && OPENRASP_TAINT_POSSIBLE(z);
                bool is_value_tainted_string = value && IS_STRING == Z_TYPE_P(value) && OPENRASP_TAINT_POSSIBLE(value);
                NodeSequence ns_no_get_ptr;
                if (is_z_tainted_string || is_value_tainted_string)
                {
                    ns_no_get_ptr.append(OPENRASP_TAINT_SEQUENCE(z));
                    ns_no_get_ptr.append(OPENRASP_TAINT_SEQUENCE(value));
                }

                SEPARATE_ZVAL_IF_NOT_REF(&z);
                binary_op(z, z, value TSRMLS_CC);
                if (ns_no_get_ptr.taintedSize() && IS_STRING == Z_TYPE_P(z) && Z_STRLEN_P(z) && ns_no_get_ptr.length() == Z_STRLEN_P(z))
                {
                    Z_STRVAL_P(z) = (char *)erealloc(Z_STRVAL_P(z), Z_STRLEN_P(z) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
                    OPENRASP_TAINT_MARK(z, new NodeSequence(ns_no_get_ptr));
                }

                switch (opline->extended_value)
                {
                case ZEND_ASSIGN_OBJ:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
                    Z_OBJ_HT_P(object)->write_property(object, property, z TSRMLS_CC);
#else
                    Z_OBJ_HT_P(object)->write_property(object, property, z, ((OPENRASP_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL) TSRMLS_CC);
#endif
                    break;
                case ZEND_ASSIGN_DIM:
                    Z_OBJ_HT_P(object)->write_dimension(object, property, z TSRMLS_CC);
                    break;
                }
                if (OPENRASP_RETURN_VALUE_USED(opline))
                {
                    *retval = z;
                    Z_ADDREF_P(*retval);
                }
                zval_ptr_dtor(&z);
            }
            else
            {
                zend_error(E_WARNING, "Attempt to assign property of non-object");
                if (OPENRASP_RETURN_VALUE_USED(opline))
                {
                    *retval = EG(uninitialized_zval_ptr);
                    Z_ADDREF_P(*retval);
                }
            }
        }

        switch (OPENRASP_OP2_TYPE(opline))
        {
        case IS_TMP_VAR:
            zval_ptr_dtor(&property);
            break;
        case IS_VAR:
            if (free_op2.var)
            {
                zval_ptr_dtor(&free_op2.var);
            };
            break;
        case IS_CV:
        case IS_CONST:
        case IS_UNUSED:
        default:
            /* do nothing */
            break;
        }

        OPENRASP_FREE_OP(free_op_data1);
    }

    if (IS_VAR == OPENRASP_OP1_TYPE(opline) && free_op1.var)
    {
        zval_ptr_dtor(&free_op1.var);
    };
    /* assign_obj has two opcodes! */
    execute_data->opline++;
    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

static int openrasp_binary_assign_op_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    openrasp_free_op free_op1 = {0}, free_op2 = {0}, free_op_data2 = {0}, free_op_data1 = {0};
    zval **var_ptr = NULL, **object_ptr = NULL, *value = NULL;
    zend_bool increment_opline = 0;

    switch (opline->extended_value)
    {
    case ZEND_ASSIGN_OBJ:
        return openrasp_binary_assign_op_obj_helper(binary_op, ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
        break;
    case ZEND_ASSIGN_DIM:
    {
        switch (OPENRASP_OP1_TYPE(opline))
        {
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            object_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
            object_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            if (object_ptr && !(free_op1.var != NULL))
            {
                Z_ADDREF_P(*object_ptr); /* undo the effect of get_obj_zval_ptr_ptr() */
            }
            break;
        case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            object_ptr = openrasp_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_W TSRMLS_CC);
#else
            object_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W TSRMLS_CC);
#endif
            break;
        case IS_UNUSED:
            object_ptr = openrasp_get_obj_zval_ptr_ptr_unused(TSRMLS_C);
            if (object_ptr)
            {
                Z_ADDREF_P(*object_ptr); /* undo the effect of get_obj_zval_ptr_ptr() */
            }
            break;
        default:
            /* do nothing */
            break;
        }

        if (object_ptr && Z_TYPE_PP(object_ptr) == IS_OBJECT)
        {
            return openrasp_binary_assign_op_obj_helper(binary_op, ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
        }
        else
        {
            zend_op *op_data = opline + 1;

            zval *dim;

            switch (OPENRASP_OP2_TYPE(opline))
            {
            case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
                dim = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
                dim = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
                break;
            case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
                dim = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
                dim = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
                break;
            case IS_CV:
                dim = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
                break;
            case IS_CONST:
                dim = OPENRASP_OP2_CONSTANT_PTR(opline);
                break;
            case IS_UNUSED:
                dim = NULL;
                break;
            default:
                /* do nothing */
                break;
            }

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            if (OPENRASP_OP2_TYPE(opline) == IS_TMP_VAR)
            {
                openrasp_fetch_dimension_address(&OPENRASP_T(OPENRASP_OP2_VAR(op_data)), object_ptr, dim, 1, BP_VAR_RW TSRMLS_CC);
            }
            else
            {
                openrasp_fetch_dimension_address(&OPENRASP_T(OPENRASP_OP2_VAR(op_data)), object_ptr, dim, 0, BP_VAR_RW TSRMLS_CC);
            }
            value = openrasp_get_zval_ptr(&op_data->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
            var_ptr = openrasp_get_zval_ptr_ptr(&op_data->op2, execute_data->Ts, &free_op_data2, BP_VAR_RW TSRMLS_CC);
#else
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            openrasp_fetch_dimension_address(&OPENRASP_T((opline + 1)->op2.var), object_ptr, dim, IS_TMP_VAR, BP_VAR_RW TSRMLS_CC);
            value = openrasp_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data, &free_op_data1, BP_VAR_R TSRMLS_CC);
            var_ptr = openrasp_get_zval_ptr_ptr_var((opline + 1)->op2.var, execute_data, &free_op_data2 TSRMLS_CC);
#else
            openrasp_fetch_dimension_address(&OPENRASP_T(OPENRASP_OP2_VAR(op_data)), object_ptr, dim, OPENRASP_OP2_TYPE(opline), BP_VAR_RW TSRMLS_CC);
            value = openrasp_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
            var_ptr = openrasp_get_zval_ptr_ptr_var((opline + 1)->op2.var, execute_data->Ts, &free_op_data2 TSRMLS_CC);
#endif
#endif
            increment_opline = 1;
        }
    }
    break;
    default:
        switch (OPENRASP_OP2_TYPE(opline))
        {
        case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            value = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
            value = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
            break;
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            value = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
            value = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
            break;
        case IS_CV:
            value = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
            break;
        case IS_CONST:
            value = OPENRASP_OP2_CONSTANT_PTR(opline);
            break;
        case IS_UNUSED:
            value = NULL;
            break;
        default:
            /* do nothing */
            break;
        }

        switch (OPENRASP_OP1_TYPE(opline))
        {
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            var_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
            var_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            var_ptr = openrasp_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_RW TSRMLS_CC);
#else
            var_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_RW TSRMLS_CC);
#endif
            break;
        case IS_UNUSED:
            var_ptr = NULL;
            break;
        default:
            /* do nothing */
            break;
        }
        /* do nothing */
        break;
    }

    if (!var_ptr)
    {
        zend_error(E_ERROR, "Cannot use assign-op operators with overloaded objects nor string offsets");
        return 0;
    }

    if (*var_ptr == EG(error_zval_ptr))
    {
        if (OPENRASP_RETURN_VALUE_USED(opline))
        {
            OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr = &EG(uninitialized_zval_ptr);
            Z_ADDREF_P(*OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr);
            OPENRASP_AI_USE_PTR(OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var);
        }

        switch (OPENRASP_OP2_TYPE(opline))
        {
        case IS_TMP_VAR:
            zval_dtor(free_op2.var);
            break;
        case IS_VAR:
            if (free_op2.var)
            {
                zval_ptr_dtor(&free_op2.var);
            };
            break;
        case IS_CV:
        case IS_CONST:
        case IS_UNUSED:
        default:
            /* do nothing */
            break;
        }

        if (IS_VAR == OPENRASP_OP1_TYPE(opline) && free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        };
        if (increment_opline)
        {
            execute_data->opline++;
        }
        execute_data->opline++;
    }

    SEPARATE_ZVAL_IF_NOT_REF(var_ptr);

    bool is_value_tainted_string = value && IS_STRING == Z_TYPE_P(value) && OPENRASP_TAINT_POSSIBLE(value);

    if (Z_TYPE_PP(var_ptr) == IS_OBJECT && Z_OBJ_HANDLER_PP(var_ptr, get) && Z_OBJ_HANDLER_PP(var_ptr, set))
    {
        /* proxy object */
        zval *objval = Z_OBJ_HANDLER_PP(var_ptr, get)(*var_ptr TSRMLS_CC);
        Z_ADDREF_P(objval);
        bool is_objval_tainted_string = objval && IS_STRING == Z_TYPE_P(objval) && OPENRASP_TAINT_POSSIBLE(objval);
        NodeSequence ns_obj;
        if (is_objval_tainted_string || is_value_tainted_string)
        {
            ns_obj.append(OPENRASP_TAINT_SEQUENCE(objval));
            ns_obj.append(OPENRASP_TAINT_SEQUENCE(value));
        }
        binary_op(objval, objval, value TSRMLS_CC);
        if (ns_obj.taintedSize() && IS_STRING == Z_TYPE_P(objval) && Z_STRLEN_P(objval) && ns_obj.length() == Z_STRLEN_P(objval))
        {
            Z_STRVAL_P(objval) = (char *)erealloc(Z_STRVAL_P(objval), Z_STRLEN_P(objval) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(objval, new NodeSequence(ns_obj));
        }

        Z_OBJ_HANDLER_PP(var_ptr, set)
        (var_ptr, objval TSRMLS_CC);
        zval_ptr_dtor(&objval);
    }
    else
    {
        bool is_var_ptr_tainted_string = *var_ptr && IS_STRING == Z_TYPE_PP(var_ptr) && OPENRASP_TAINT_POSSIBLE(*var_ptr);
        NodeSequence ns_nonobj;
        if (is_var_ptr_tainted_string || is_value_tainted_string)
        {
            ns_nonobj.append(OPENRASP_TAINT_SEQUENCE(*var_ptr));
            ns_nonobj.append(OPENRASP_TAINT_SEQUENCE(value));
        }
        binary_op(*var_ptr, *var_ptr, value TSRMLS_CC);
        if (ns_nonobj.taintedSize() && IS_STRING == Z_TYPE_PP(var_ptr) && Z_STRLEN_PP(var_ptr) && ns_nonobj.length() == Z_STRLEN_PP(var_ptr))
        {
            Z_STRVAL_PP(var_ptr) = (char *)erealloc(Z_STRVAL_PP(var_ptr), Z_STRLEN_PP(var_ptr) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(*var_ptr, new NodeSequence(ns_nonobj));
        }
    }

    if (OPENRASP_RETURN_VALUE_USED(opline))
    {
        OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr = var_ptr;
        Z_ADDREF_P(*var_ptr);
        OPENRASP_AI_USE_PTR(OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var);
    }

    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op2.var);
        break;
    case IS_VAR:
        if (free_op2.var)
        {
            zval_ptr_dtor(&free_op2.var);
        };
        break;
    case IS_CV:
    case IS_CONST:
    case IS_UNUSED:
    default:
        /* do nothing */
        break;
    }

    if (increment_opline)
    {
        execute_data->opline++;
        OPENRASP_FREE_OP(free_op_data1);
        OPENRASP_FREE_OP_VAR_PTR(free_op_data2);
    }
    if (IS_VAR == OPENRASP_OP1_TYPE(opline) && free_op1.var)
    {
        zval_ptr_dtor(&free_op1.var);
    }

    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource TSRMLS_DC)
{
    HashTable *ht = Z_ARRVAL_P(symbol_table);

    for (zend_hash_internal_pointer_reset(ht);
         zend_hash_has_more_elements(ht) == SUCCESS;
         zend_hash_move_forward(ht))
    {
        char *key;
        ulong idx;
        int type;
        type = zend_hash_get_current_key(ht, &key, &idx, 0);
        if (type == HASH_KEY_NON_EXISTENT)
        {
            continue;
        }
        zval **ele_value;
        if (zend_hash_get_current_data(ht, (void **)&ele_value) != SUCCESS)
        {
            continue;
        }
        if (Z_TYPE_PP(ele_value) == IS_ARRAY)
        {
            openrasp_taint_mark_strings(*ele_value, varsSource TSRMLS_CC);
        }
        else if (IS_STRING == Z_TYPE_PP(ele_value))
        {
            std::string name;
            if (type == HASH_KEY_IS_STRING)
            {
                name = std::string(key);
            }
            else if (type == HASH_KEY_IS_LONG)
            {
                long actual = idx;
                name = std::to_string(actual);
            }
            Z_STRVAL_PP(ele_value) = (char *)erealloc(Z_STRVAL_PP(ele_value), Z_STRLEN_PP(ele_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(*ele_value, new NodeSequence(Z_STRLEN_PP(ele_value), varsSource, name, true));
        }
    }
}

void openrasp_taint_deep_copy(zval *source, zval *target TSRMLS_DC)
{
    switch (Z_TYPE_P(source) & IS_CONSTANT_TYPE_MASK)
    {
    case IS_STRING:
        str_unchanege_taint(source, target TSRMLS_CC);
        break;
    case IS_ARRAY:
    {
        HashTable *ht = Z_ARRVAL_P(source);

        for (zend_hash_internal_pointer_reset(ht);
             zend_hash_has_more_elements(ht) == SUCCESS;
             zend_hash_move_forward(ht))
        {
            char *key;
            ulong idx;
            int type;
            type = zend_hash_get_current_key(ht, &key, &idx, 0);
            if (type == HASH_KEY_NON_EXISTENT)
            {
                continue;
            }
            zval **source_ele_value;
            zval **target_ele_value;
            if (zend_hash_get_current_data(ht, (void **)&source_ele_value) != SUCCESS)
            {
                continue;
            }
            if (type == HASH_KEY_IS_STRING)
            {
                if (zend_hash_find(Z_ARRVAL_P(target), key, strlen(key) + 1, (void **)&target_ele_value) == SUCCESS &&
                    Z_TYPE_PP(source_ele_value) == Z_TYPE_PP(target_ele_value))
                {
                    openrasp_taint_deep_copy(*source_ele_value, *target_ele_value TSRMLS_CC);
                }
            }
            else if (type == HASH_KEY_IS_LONG)
            {
                 if (zend_hash_index_find(Z_ARRVAL_P(target), idx, (void **)&target_ele_value) == SUCCESS &&
                    Z_TYPE_PP(source_ele_value) == Z_TYPE_PP(target_ele_value))
                {
                    openrasp_taint_deep_copy(*source_ele_value, *target_ele_value TSRMLS_CC);
                }
            }
        }
    }
    break;
    }
}

static void openrasp_pzval_unlock_func(zval *z, openrasp_free_op *should_free, int unref)
{
    if (!Z_DELREF_P(z))
    {
        Z_SET_REFCOUNT_P(z, 1);
        Z_UNSET_ISREF_P(z);
        should_free->var = z;
    }
    else
    {
        should_free->var = 0;
        if (unref && Z_ISREF_P(z) && Z_REFCOUNT_P(z) == 1)
        {
            should_free->is_ref = 1;
            Z_UNSET_ISREF_P(z);
        }
    }
}

static void openrasp_pzval_unlock_free_func(zval *z)
{
    if (!Z_DELREF_P(z))
    {
        zval_dtor(z);
        efree(z);
    }
}

static void openrasp_pzval_lock_func(zval *z, openrasp_free_op *should_free)
{
    if (should_free->type == IS_VAR)
    {
        Z_ADDREF_P(z);
        if (should_free->var && should_free->is_ref)
        {
            Z_SET_ISREF_P(z);
        }
    }
}

static zval **openrasp_fetch_dimension_address_inner(HashTable *ht, zval *dim, int dim_type, int type TSRMLS_DC)
{
    zval **retval;
    char *offset_key;
    int offset_key_length;
    ulong hval;

    switch (dim->type)
    {
    case IS_NULL:
        offset_key = "";
        offset_key_length = 0;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 3)
        hval = zend_inline_hash_func("", 1);
#endif
        goto fetch_string_dim;

    case IS_STRING:
        offset_key = dim->value.str.val;
        offset_key_length = dim->value.str.len;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 3)
        if (dim_type == IS_CONST)
        {
            hval = Z_HASH_P(dim);
        }
        else
        {
            ZEND_HANDLE_NUMERIC_EX(offset_key, offset_key_length + 1, hval, goto num_index);
            if (IS_INTERNED(offset_key))
            {
                hval = INTERNED_HASH(offset_key);
            }
            else
            {
                hval = zend_hash_func(offset_key, offset_key_length + 1);
            }
        }
#endif

    fetch_string_dim:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
        if (zend_symtable_find(ht, offset_key, offset_key_length + 1, (void **)&retval) == FAILURE)
        {
#else
        if (zend_hash_quick_find(ht, offset_key, offset_key_length + 1, hval, (void **)&retval) == FAILURE)
        {
#endif
            switch (type)
            {
            case BP_VAR_R:
                zend_error(E_NOTICE, "Undefined index: %s", offset_key);
                /* break missing intentionally */
            case BP_VAR_UNSET:
            case BP_VAR_IS:
                retval = &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined index: %s", offset_key);
                /* break missing intentionally */
            case BP_VAR_W:
            {
                zval *new_zval = &EG(uninitialized_zval);
                Z_ADDREF_P(new_zval);
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
                zend_symtable_update(ht, offset_key, offset_key_length + 1, &new_zval, sizeof(zval *), (void **)&retval);
#else
                zend_hash_quick_update(ht, offset_key, offset_key_length + 1, hval, &new_zval, sizeof(zval *), (void **)&retval);
#endif
            }
            break;
            }
        }
#if 0
			}
#endif
        break;
    case IS_DOUBLE:
        hval = zend_dval_to_lval(Z_DVAL_P(dim));
        goto num_index;
    case IS_RESOURCE:
        zend_error(E_STRICT, "Resource ID#%ld used as offset, casting to integer (%ld)", Z_LVAL_P(dim), Z_LVAL_P(dim));
        /* Fall Through */
    case IS_BOOL:
    case IS_LONG:
        hval = Z_LVAL_P(dim);
    num_index:
        if (zend_hash_index_find(ht, hval, (void **)&retval) == FAILURE)
        {
            switch (type)
            {
            case BP_VAR_R:
                zend_error(E_NOTICE, "Undefined offset: %ld", hval);
                /* break missing intentionally */
            case BP_VAR_UNSET:
            case BP_VAR_IS:
                retval = &EG(uninitialized_zval_ptr);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined offset: %ld", hval);
                /* break missing intentionally */
            case BP_VAR_W:
            {
                zval *new_zval = &EG(uninitialized_zval);

                Z_ADDREF_P(new_zval);
                zend_hash_index_update(ht, hval, &new_zval, sizeof(zval *), (void **)&retval);
            }
            break;
            }
        }
        break;

    default:
        zend_error(E_WARNING, "Illegal offset type");
        return (type == BP_VAR_W || type == BP_VAR_RW) ? &EG(error_zval_ptr) : &EG(uninitialized_zval_ptr);
    }
    return retval;
}

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
static void openrasp_fetch_dimension_address(temp_variable *result, zval **container_ptr, zval *dim, int dim_is_tmp_var, int type TSRMLS_DC)
#else
static void openrasp_fetch_dimension_address(temp_variable *result, zval **container_ptr, zval *dim, int dim_type, int type TSRMLS_DC)
#endif
{
    zval *container = *container_ptr;
    zval **retval;

    switch (Z_TYPE_P(container))
    {

    case IS_ARRAY:
        if (type != BP_VAR_UNSET && Z_REFCOUNT_P(container) > 1 && !Z_ISREF_P(container))
        {
            SEPARATE_ZVAL(container_ptr);
            container = *container_ptr;
        }
    fetch_from_array:
        if (dim == NULL)
        {
            zval *new_zval = &EG(uninitialized_zval);

            Z_ADDREF_P(new_zval);
            if (zend_hash_next_index_insert(Z_ARRVAL_P(container), &new_zval, sizeof(zval *), (void **)&retval) == FAILURE)
            {
                zend_error(E_WARNING, "Cannot add element to the array as the next element is already occupied");
                retval = &EG(error_zval_ptr);
                Z_DELREF_P(new_zval);
            }
        }
        else
        {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            retval = openrasp_fetch_dimension_address_inner(Z_ARRVAL_P(container), dim, 0, type TSRMLS_CC);
#else
            retval = openrasp_fetch_dimension_address_inner(Z_ARRVAL_P(container), dim, dim_type, type TSRMLS_CC);
#endif
        }
        result->var.ptr_ptr = retval;
        Z_ADDREF_P(*retval);
        return;
        break;

    case IS_NULL:
        if (container == &EG(error_zval))
        {
            result->var.ptr_ptr = &EG(error_zval_ptr);
            Z_ADDREF_P(EG(error_zval_ptr));
        }
        else if (type != BP_VAR_UNSET)
        {
        convert_to_array:
            if (!Z_ISREF_P(container))
            {
                SEPARATE_ZVAL(container_ptr);
                container = *container_ptr;
            }
            zval_dtor(container);
            array_init(container);
            goto fetch_from_array;
        }
        else
        {
            /* for read-mode only */
            result->var.ptr_ptr = &EG(uninitialized_zval_ptr);
            Z_ADDREF_P(EG(uninitialized_zval_ptr));
        }
        return;
        break;

    case IS_STRING:
    {
        zval tmp;

        if (type != BP_VAR_UNSET && Z_STRLEN_P(container) == 0)
        {
            goto convert_to_array;
        }
        if (dim == NULL)
        {
            zend_error(E_ERROR, "[] operator not supported for strings");
            return;
        }

        if (Z_TYPE_P(dim) != IS_LONG)
        {

            switch (Z_TYPE_P(dim))
            {
            /* case IS_LONG: */
            case IS_STRING:
                if (IS_LONG == is_numeric_string(Z_STRVAL_P(dim), Z_STRLEN_P(dim), NULL, NULL, -1))
                {
                    break;
                }
                if (type != BP_VAR_UNSET)
                {
                    zend_error(E_WARNING, "Illegal string offset '%s'", dim->value.str.val);
                }

                break;
            case IS_DOUBLE:
            case IS_NULL:
            case IS_BOOL:
                zend_error(E_NOTICE, "String offset cast occurred");
                break;
            default:
                zend_error(E_WARNING, "Illegal offset type");
                break;
            }

            tmp = *dim;
            zval_copy_ctor(&tmp);
            convert_to_long(&tmp);
            dim = &tmp;
        }
        if (type != BP_VAR_UNSET)
        {
            SEPARATE_ZVAL_IF_NOT_REF(container_ptr);
        }
        container = *container_ptr;
        result->str_offset.str = container;
        Z_ADDREF_P(container);
        result->str_offset.offset = Z_LVAL_P(dim);
        result->str_offset.ptr_ptr = NULL;
        return;
    }
    break;

    case IS_OBJECT:
        if (!Z_OBJ_HT_P(container)->read_dimension)
        {
            zend_error(E_ERROR, "Cannot use object as array");
            return;
        }
        else
        {
            zval *overloaded_result;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            if (dim_is_tmp_var)
            {
#else
            if (dim_type == IS_TMP_VAR)
            {
#endif
                zval *orig = dim;
                MAKE_REAL_ZVAL_PTR(dim);
                ZVAL_NULL(orig);
            }
#if 0
				}
#endif
            overloaded_result = Z_OBJ_HT_P(container)->read_dimension(container, dim, type TSRMLS_CC);

            if (overloaded_result)
            {
                if (!Z_ISREF_P(overloaded_result))
                {
                    if (Z_REFCOUNT_P(overloaded_result) > 0)
                    {
                        zval *tmp = overloaded_result;

                        ALLOC_ZVAL(overloaded_result);
                        /* ZVAL_COPY_VALUE(overloaded_result, tmp); */
                        overloaded_result->value = tmp->value;
                        Z_TYPE_P(overloaded_result) = Z_TYPE_P(tmp);
                        zval_copy_ctor(overloaded_result);
                        Z_UNSET_ISREF_P(overloaded_result);
                        Z_SET_REFCOUNT_P(overloaded_result, 0);
                    }
                    if (Z_TYPE_P(overloaded_result) != IS_OBJECT)
                    {
                        zend_class_entry *ce = Z_OBJCE_P(container);
                        zend_error(E_NOTICE, "Indirect modification of overloaded element of %s has no effect", ce->name);
                    }
                }
                retval = &overloaded_result;
            }
            else
            {
                retval = &EG(error_zval_ptr);
            }
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            OPENRASP_AI_SET_PTR(result->var, *retval);
#else
            OPENRASP_AI_SET_PTR(result, *retval);
#endif
            Z_ADDREF_P(*retval);
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            if (dim_is_tmp_var)
            {
#else
            if (dim_type == IS_TMP_VAR)
            {
#endif
                zval_ptr_dtor(&dim);
            }
#if 0
				}
#endif
        }
        return;
        break;

    case IS_BOOL:
        if (type != BP_VAR_UNSET && Z_LVAL_P(container) == 0)
        {
            goto convert_to_array;
        }
        /* break missing intentionally */

    default:
        if (type == BP_VAR_UNSET)
        {
            zend_error(E_WARNING, "Cannot unset offset in a non-array variable");
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
            OPENRASP_AI_SET_PTR(result->var, EG(uninitialized_zval_ptr));
#else
            OPENRASP_AI_SET_PTR(result, &EG(uninitialized_zval));
#endif
            Z_ADDREF_P(&EG(uninitialized_zval));
        }
        else
        {
            zend_error(E_WARNING, "Cannot use a scalar value as an array");
            result->var.ptr_ptr = &EG(error_zval_ptr);
            Z_ADDREF_P(EG(error_zval_ptr));
        }
        break;
    }
#if 0
}
#endif
}

int openrasp_add_char_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL, *result;
    openrasp_free_op free_op1 = {0};

    result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    op1 = result;
    if (OPENRASP_OP1_TYPE(opline) == IS_UNUSED)
    {
        /* Initialize for erealloc in add_string_to_string */
        Z_STRVAL_P(op1) = NULL;
        Z_STRLEN_P(op1) = 0;
        Z_TYPE_P(op1) = IS_STRING;
        INIT_PZVAL(op1);
    }
    else
    {
#endif
        switch (OPENRASP_OP1_TYPE(opline))
        {
        case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_CV:
            op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
            break;
        case IS_CONST:
            op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
            break;
        }
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    }
#endif

    bool is_op1_tainted_string = op1 && IS_STRING == Z_TYPE_P(op1) &&
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
                                 Z_STRVAL_P(op1) &&
#endif
                                 OPENRASP_TAINT_POSSIBLE(op1);
    NodeSequence ns;
    if (is_op1_tainted_string)
    {
        ns.append(OPENRASP_TAINT_SEQUENCE(op1));
        ns.append(1);
    }

    add_char_to_string(result, op1, OPENRASP_OP2_CONSTANT_PTR(opline));

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result) && ns.length() == Z_STRLEN_P(result))
    {
        Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(result, new NodeSequence(ns));
    }

    /* FREE_OP is missing intentionally here - we're always working on the same temporary variable */
    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_assign_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval **op1 = NULL;
    zval *op2 = NULL;
    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_VAR:
        op2 = OPENRASP_T(OPENRASP_OP2_VAR(opline)).var.ptr;
        break;
    case IS_CV:
    {
        zval **t = OPENRASP_CV_OF(OPENRASP_OP2_VAR(opline));
        if (t && *t)
        {
            op2 = *t;
        }
        else if (EG(active_symbol_table))
        {
            zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(OPENRASP_OP2_VAR(opline));
            if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)&t) == SUCCESS)
            {
                op2 = *t;
            }
        }
    }
    break;
    default:
        return ZEND_USER_OPCODE_DISPATCH;
        break;
    }

    if (!op2 ||
        op2 == &EG(error_zval) ||
        Z_TYPE_P(op2) != IS_STRING ||
        !Z_STRLEN_P(op2) ||
        !OPENRASP_TAINT_POSSIBLE(op2))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        op1 = OPENRASP_T(OPENRASP_OP1_VAR(opline)).var.ptr_ptr;
        break;
    case IS_CV:
    {
        zval **t = OPENRASP_CV_OF(OPENRASP_OP1_VAR(opline));
        if (t && *t)
        {
            op1 = t;
        }
        else if (EG(active_symbol_table))
        {
            zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(OPENRASP_OP1_VAR(opline));
            if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)&t) == SUCCESS)
            {
                op1 = t;
            }
        }
    }
    break;
    }

    if (op1 && *op1 != &EG(error_zval) && Z_TYPE_PP(op1) != IS_OBJECT && PZVAL_IS_REF(*op1) && IS_TMP_VAR != OPENRASP_OP2_TYPE(opline))
    {
        zval garbage = **op1;
        zend_uint refcount = Z_REFCOUNT_PP(op1);

        **op1 = *op2;
        Z_SET_REFCOUNT_P(*op1, refcount);
        Z_SET_ISREF_PP(op1);
        zval_copy_ctor(*op1);
        zval_dtor(&garbage);
        Z_STRVAL_PP(op1) = (char *)erealloc(Z_STRVAL_PP(op1), Z_STRLEN_PP(op1) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(*op1, new NodeSequence(OPENRASP_TAINT_SEQUENCE(op2)));

        execute_data->opline++;
        return ZEND_USER_OPCODE_CONTINUE;
    }
    else if (PZVAL_IS_REF(op2) && Z_REFCOUNT_P(op2) > 1)
    {
        SEPARATE_ZVAL(&op2);
        Z_STRVAL_P(op2) = (char *)erealloc(Z_STRVAL_P(op2), Z_STRLEN_P(op2) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(op2, new NodeSequence(OPENRASP_TAINT_SEQUENCE(op2)));
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

int openrasp_add_var_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL, *op2 = NULL, *result;
    openrasp_free_op free_op1 = {0}, free_op2 = {0};
    zval var_copy;
    int use_copy = 0;

    result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    op1 = result;
    if (OPENRASP_OP1_TYPE(opline) == IS_UNUSED)
    {
        /* Initialize for erealloc in add_string_to_string */
        Z_STRVAL_P(op1) = NULL;
        Z_STRLEN_P(op1) = 0;
        Z_TYPE_P(op1) = IS_STRING;
        INIT_PZVAL(op1);
    }
    else
    {
#endif
        switch (OPENRASP_OP1_TYPE(opline))
        {
        case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif

            break;
        case IS_CV:
            op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
            break;
        case IS_CONST:
            op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
            break;
        }
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    }
#endif

    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;
    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op2 = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        op2 = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        op2 = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;
    case IS_CONST:
        op2 = OPENRASP_OP2_CONSTANT_PTR(opline);
        break;
    }

    bool is_op1_tainted_string = op1 && IS_STRING == Z_TYPE_P(op1)
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
                                 && Z_STRVAL_P(op1)
#endif
                                 && OPENRASP_TAINT_POSSIBLE(op1);

    bool is_op2_tainted_string = op2 && IS_STRING == Z_TYPE_P(op2)
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
                                 && Z_STRVAL_P(op2)
#endif
                                 && OPENRASP_TAINT_POSSIBLE(op2);

    NodeSequence ns;
    if (is_op1_tainted_string || is_op2_tainted_string)
    {
        ns.append(OPENRASP_TAINT_SEQUENCE(op1));
        ns.append(OPENRASP_TAINT_SEQUENCE(op2));
    }

    if (Z_TYPE_P(op2) != IS_STRING)
    {
        zend_make_printable_zval(op2, &var_copy, &use_copy);
        if (use_copy)
        {
            op2 = &var_copy;
        }
    }

    add_string_to_string(result, op1, op2);

    if (use_copy)
    {
        zval_dtor(op2);
    }

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result) && ns.length() == Z_STRLEN_P(result))
    {
        Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(result, new NodeSequence(ns));
    }

    /* original comment, possibly problematic:
	 * FREE_OP is missing intentionally here - we're always working on the same temporary variable
	 * (Zeev):  I don't think it's problematic, we only use variables
	 * which aren't affected by FREE_OP(Ts, )'s anyway, unless they're
	 * string offsets or overloaded objects
	 */
    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op2.var);
        break;
    case IS_VAR:
        if (free_op2.var)
        {
            zval_ptr_dtor(&free_op2.var);
        }
        break;
    }

    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_add_string_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL, *result;
    openrasp_free_op free_op1 = {0};

    result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    op1 = result;
    if (OPENRASP_OP1_TYPE(opline) == IS_UNUSED)
    {
        /* Initialize for erealloc in add_string_to_string */
        Z_STRVAL_P(op1) = NULL;
        Z_STRLEN_P(op1) = 0;
        Z_TYPE_P(op1) = IS_STRING;
        INIT_PZVAL(op1);
    }
    else
    {
#endif
        switch (OPENRASP_OP1_TYPE(opline))
        {
        case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
            op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
            break;
        case IS_CV:
            op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
            break;
        case IS_CONST:
            op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
            break;
        }
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
    }
#endif

    bool is_op1_tainted_string = op1 && IS_STRING == Z_TYPE_P(op1) &&
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
                                 Z_STRVAL_P(op1) &&
#endif
                                 OPENRASP_TAINT_POSSIBLE(op1);
    NodeSequence ns;
    if (is_op1_tainted_string)
    {
        ns.append(OPENRASP_TAINT_SEQUENCE(op1));
        ns.append(Z_STRLEN_P(OPENRASP_OP2_CONSTANT_PTR(opline)));
    }

    add_string_to_string(result, op1, OPENRASP_OP2_CONSTANT_PTR(opline));

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result) && ns.length() == Z_STRLEN_P(result))
    {
        Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(result, new NodeSequence(ns));
    }

    /* FREE_OP is missing intentionally here - we're always working on the same temporary variable */
    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_assign_ref_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    if (opline->extended_value == ZEND_RETURNS_FUNCTION && OPENRASP_OP2_TYPE(opline) == IS_VAR)
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    openrasp_free_op free_op1 = {0}, free_op2 = {0};
    zval **variable_ptr_ptr;
    zval **value_ptr_ptr;
    int variable_type = 0;
    int value_type = 0;
    switch (OPENRASP_OP2_TYPE(opline))
    {
    case IS_VAR:
        value_type = IS_VAR;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        value_ptr_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        value_ptr_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        value_type = IS_CV;
        value_ptr_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op2.var, BP_VAR_W TSRMLS_CC);
        break;
    }
    if (!value_ptr_ptr ||
        *value_ptr_ptr == &EG(error_zval) ||
        IS_STRING != Z_TYPE_PP(value_ptr_ptr) ||
        PZVAL_IS_REF(*value_ptr_ptr) ||
        !Z_STRLEN_PP(value_ptr_ptr) ||
        !OPENRASP_TAINT_POSSIBLE(*value_ptr_ptr))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    if (value_type == IS_VAR)
    {
        if (value_ptr_ptr &&
            !Z_ISREF_PP(value_ptr_ptr) &&
            opline->extended_value == ZEND_RETURNS_FUNCTION &&
            !OPENRASP_T(opline->op2.var).var.fcall_returned_reference)
        {
            if (free_op2.var == NULL)
            {
                OPENRASP_PZVAL_LOCK(*value_ptr_ptr); /* undo the effect of get_zval_ptr_ptr() */
            }
            zend_error(E_STRICT, "Only variables should be assigned by reference");
            if (UNEXPECTED(EG(exception) != NULL))
            {
                if (free_op2.var)
                {
                    zval_ptr_dtor(&free_op2.var);
                };
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
                execute_data->opline++;
#endif
                ZEND_VM_CONTINUE();
            }
            return ZEND_USER_OPCODE_DISPATCH;
        }
        else if (opline->extended_value == ZEND_RETURNS_NEW)
        {
            OPENRASP_PZVAL_LOCK(*value_ptr_ptr);
        }
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        variable_type = IS_VAR;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        variable_ptr_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        variable_ptr_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        variable_type = IS_CV;
        variable_ptr_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W TSRMLS_CC);
        break;
    }

    if (variable_type == IS_VAR)
    {
        if (UNEXPECTED(OPENRASP_T(opline->op1.var).var.ptr_ptr == &OPENRASP_T(opline->op1.var).var.ptr))
        {
            zend_error_noreturn(E_ERROR, "Cannot assign by reference to overloaded object");
        }
    }

    if ((value_type == IS_VAR && UNEXPECTED(variable_ptr_ptr == NULL)))
    {
        zend_error_noreturn(E_ERROR, "Cannot create references to/from string offsets nor overloaded objects");
    }
    if (variable_type == IS_VAR && UNEXPECTED(value_ptr_ptr == NULL))
    {
        zend_error_noreturn(E_ERROR, "Cannot create references to/from string offsets nor overloaded objects");
    }

    openrasp_assign_to_variable_reference(variable_ptr_ptr, value_ptr_ptr TSRMLS_CC);

    if (variable_type == IS_VAR && opline->extended_value == ZEND_RETURNS_NEW)
    {
        Z_DELREF_PP(variable_ptr_ptr);
    }

    if (OPENRASP_RETURN_VALUE_USED(opline))
    {
        OPENRASP_PZVAL_LOCK(*variable_ptr_ptr);
        OPENRASP_AI_SET_PTR(&OPENRASP_T(opline->result.var), *variable_ptr_ptr);
    }
    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

static void openrasp_assign_to_variable_reference(zval **variable_ptr_ptr, zval **value_ptr_ptr TSRMLS_DC)
{
    zval *variable_ptr = *variable_ptr_ptr; //op1
    zval *value_ptr = *value_ptr_ptr;       //op2
    bool is_value_ptr_tainted_string = value_ptr && IS_STRING == Z_TYPE_P(value_ptr) &&
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)
                                       Z_STRVAL_P(value_ptr) &&
#endif
                                       OPENRASP_TAINT_POSSIBLE(value_ptr);
    NodeSequence ns;
    if (is_value_ptr_tainted_string)
    {
        ns = OPENRASP_TAINT_SEQUENCE(value_ptr);
    }

    if (variable_ptr == &EG(error_zval) || value_ptr == &EG(error_zval))
    {
        variable_ptr_ptr = &EG(uninitialized_zval_ptr);
    }
    else if (variable_ptr != value_ptr)
    {
        if (!PZVAL_IS_REF(value_ptr))
        {
            /* break it away */
            Z_DELREF_P(value_ptr);
            if (Z_REFCOUNT_P(value_ptr) > 0)
            {
                ALLOC_ZVAL(*value_ptr_ptr);
                ZVAL_COPY_VALUE(*value_ptr_ptr, value_ptr);
                value_ptr = *value_ptr_ptr;
                zendi_zval_copy_ctor(*value_ptr);
                if (ns.taintedSize() && Z_TYPE_P(value_ptr) == IS_STRING && ns.length() == Z_STRLEN_P(value_ptr))
                {
                    Z_STRVAL_P(value_ptr) = (char *)erealloc(Z_STRVAL_P(value_ptr), Z_STRLEN_P(value_ptr) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
                    OPENRASP_TAINT_MARK(value_ptr, new NodeSequence(ns));
                }
            }
            Z_SET_REFCOUNT_P(value_ptr, 1);
            Z_SET_ISREF_P(value_ptr);
        }

        *variable_ptr_ptr = value_ptr;
        Z_ADDREF_P(value_ptr);

        zval_ptr_dtor(&variable_ptr);
    }
    else if (!Z_ISREF_P(variable_ptr))
    {
        if (variable_ptr_ptr == value_ptr_ptr)
        {
            SEPARATE_ZVAL(variable_ptr_ptr);
        }
        else if (variable_ptr == &EG(uninitialized_zval) || Z_REFCOUNT_P(variable_ptr) > 2)
        {
            /* we need to separate */
            Z_SET_REFCOUNT_P(variable_ptr, Z_REFCOUNT_P(variable_ptr) - 2);
            ALLOC_ZVAL(*variable_ptr_ptr);
            ZVAL_COPY_VALUE(*variable_ptr_ptr, variable_ptr);
            zval_copy_ctor(*variable_ptr_ptr);
            *value_ptr_ptr = *variable_ptr_ptr;
            Z_SET_REFCOUNT_PP(variable_ptr_ptr, 2);
        }
        Z_SET_ISREF_PP(variable_ptr_ptr);
    }
}

int openrasp_qm_assign_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL;
    openrasp_free_op free_op1 = {0};

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;
    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;
    case IS_CONST:
        op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
        break;
    }

    OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var = *op1;

    if (!((zend_uintptr_t)free_op1.var & 1L))
    {
        zval_copy_ctor(&OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var);
        if (op1 && IS_STRING == Z_TYPE_P(op1) && OPENRASP_TAINT_POSSIBLE(op1))
        {
            zval *result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;
            Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(result, new NodeSequence(OPENRASP_TAINT_SEQUENCE(op1)));
        }
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op1.var);
        break;
    case IS_VAR:
        if (free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        }
        break;
    }
    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_qm_assign_var_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL;
    zval *ret = NULL;
    openrasp_free_op free_op1 = {0};

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;
    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;
    case IS_CV:
        op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
        break;
    case IS_CONST:
        op1 = OPENRASP_OP1_CONSTANT_PTR(opline);
        break;
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
    case IS_CV:
        Z_ADDREF_P(op1);
        OPENRASP_T(opline->result.var).var.ptr = op1;
        OPENRASP_T(opline->result.var).var.ptr_ptr = &OPENRASP_T(opline->result.var).var.ptr;
        break;
    default:
        ALLOC_ZVAL(ret);
        INIT_PZVAL_COPY(ret, op1);
        OPENRASP_T(opline->result.var).var.ptr = ret;
        OPENRASP_T(opline->result.var).var.ptr_ptr = &OPENRASP_T(opline->result.var).var.ptr;
        if (!((zend_uintptr_t)free_op1.var & 1L))
        {
            zval_copy_ctor(OPENRASP_T(opline->result.var).var.ptr);
            if (op1 && IS_STRING == Z_TYPE_P(op1) && OPENRASP_TAINT_POSSIBLE(op1))
            {
                zval *result = OPENRASP_T(opline->result.var).var.ptr;
                Z_STRVAL_P(result) = (char *)erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
                OPENRASP_TAINT_MARK(result, new NodeSequence(OPENRASP_TAINT_SEQUENCE(op1)));
            }
        }
        break;
    }

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
        zval_dtor(free_op1.var);
        break;
    case IS_VAR:
        if (free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        }
        break;
    }
    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_send_var_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL;
    openrasp_free_op free_op1 = {0};
    zval *varptr;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
    if ((opline->extended_value == ZEND_DO_FCALL_BY_NAME) && ARG_SHOULD_BE_SENT_BY_REF(execute_data->call->fbc, OPENRASP_OP_LINENUM(opline->op2)))
    {
        return openrasp_send_ref_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
    }
#else
    if ((opline->extended_value == ZEND_DO_FCALL_BY_NAME) && ARG_SHOULD_BE_SENT_BY_REF(execute_data->fbc, OPENRASP_OP_LINENUM(opline->op2)))
    {
        return openrasp_send_ref_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
    }
#endif
    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        op1 = OPENRASP_T(OPENRASP_OP1_VAR(opline)).var.ptr;
        break;
    case IS_CV:
    {
        op1 = openrasp_get_zval_ptr_cv(OPENRASP_OP1_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
    }
    break;
    }

    if (!op1 ||
        op1 == &EG(error_zval) ||
        op1 == &EG(uninitialized_zval) ||
        IS_STRING != Z_TYPE_P(op1) ||
        !PZVAL_IS_REF(op1) ||
        Z_REFCOUNT_P(op1) < 2 ||
        !Z_STRLEN_P(op1) ||
        !OPENRASP_TAINT_POSSIBLE(op1))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    MAKE_STD_ZVAL(varptr);
    *varptr = *op1;
    Z_SET_REFCOUNT_P(varptr, 0);
    zval_copy_ctor(varptr);
    Z_STRVAL_P(varptr) = (char *)erealloc(Z_STRVAL_P(varptr), Z_STRLEN_P(varptr) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
    OPENRASP_TAINT_MARK(varptr, new NodeSequence(OPENRASP_TAINT_SEQUENCE(op1)));

    Z_ADDREF_P(varptr);
    OPENRASP_ARG_PUSH(varptr);

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        if (free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        }
        break;
    }

    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_send_ref_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval **op1 = NULL;
    openrasp_free_op free_op1 = {0};
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION >= 5)
    if (execute_data->function_state.function->type == ZEND_INTERNAL_FUNCTION && !ARG_SHOULD_BE_SENT_BY_REF(execute_data->call->fbc, OPENRASP_OP_LINENUM(opline->op2)))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }
#else
    if (execute_data->function_state.function->type == ZEND_INTERNAL_FUNCTION && !ARG_SHOULD_BE_SENT_BY_REF(execute_data->fbc, OPENRASP_OP_LINENUM(opline->op2)))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }
#endif
    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        op1 = OPENRASP_T(OPENRASP_OP1_VAR(opline)).var.ptr_ptr;
        break;
    case IS_CV:
    {
        zval **t = OPENRASP_CV_OF(OPENRASP_OP1_VAR(opline));
        if (t && *t)
        {
            op1 = t;
        }
        else if (EG(active_symbol_table))
        {
            zend_compiled_variable *cv = &OPENRASP_CV_DEF_OF(OPENRASP_OP1_VAR(opline));
            if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)&t) == SUCCESS)
            {
                op1 = t;
            }
        }
    }
    break;
    }

    if (!op1 ||
        *op1 == &EG(error_zval) ||
        *op1 == &EG(uninitialized_zval) ||
        IS_STRING != Z_TYPE_PP(op1) ||
        PZVAL_IS_REF(*op1) ||
        Z_REFCOUNT_PP(op1) < 2 ||
        !Z_STRLEN_PP(op1) ||
        !OPENRASP_TAINT_POSSIBLE(*op1))
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    NodeSequence ns = OPENRASP_TAINT_SEQUENCE(*op1);
    SEPARATE_ZVAL_TO_MAKE_IS_REF(op1);
    Z_ADDREF_P(*op1);
    Z_STRVAL_PP(op1) = (char *)erealloc(Z_STRVAL_PP(op1), Z_STRLEN_PP(op1) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
    OPENRASP_TAINT_MARK(*op1, new NodeSequence(ns));
    OPENRASP_ARG_PUSH(*op1);

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_VAR:
        if (free_op1.var)
        {
            zval_ptr_dtor(&free_op1.var);
        }
        break;
    }

    execute_data->opline++;
    return ZEND_USER_OPCODE_CONTINUE;
}

PHP_FUNCTION(taint_dump)
{
    zval *arg;
    if (!openrasp_ini.taint_enable)
    {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE)
    {
        return;
    }

    if (IS_STRING == Z_TYPE_P(arg) && OPENRASP_TAINT_POSSIBLE(arg))
    {
        array_init(return_value);
        NodeSequence ns = OPENRASP_TAINT_SEQUENCE(arg);
        std::list<TaintNode> taintNodes = ns.getSequence();
        for (TaintNode &tn : taintNodes)
        {
            zval *z_tainted_node = nullptr;
            MAKE_STD_ZVAL(z_tainted_node);
            array_init(z_tainted_node);
            add_assoc_string(z_tainted_node, "source", (char *)tn.getSource().c_str(), 1);
            add_assoc_long(z_tainted_node, "startIndex", tn.getStartIndex());
            add_assoc_long(z_tainted_node, "endIndex", tn.getEndIndex());
            add_next_index_zval(return_value, z_tainted_node);
        }
        return;
    }

    RETURN_FALSE;
}

void str_unchanege_taint(zval *src, zval *dest TSRMLS_DC)
{
    if (Z_TYPE_P(src) == IS_STRING &&
        OPENRASP_TAINT_POSSIBLE(src) &&
        IS_STRING == Z_TYPE_P(dest) &&
        Z_STRLEN_P(src) == Z_STRLEN_P(dest))
    {
        Z_STRVAL_P(dest) = (char *)erealloc(Z_STRVAL_P(dest), Z_STRLEN_P(dest) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(dest, new NodeSequence(OPENRASP_TAINT_SEQUENCE(src)));
    }
}