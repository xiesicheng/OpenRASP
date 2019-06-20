#include "openrasp_hook.h"
#include "taint.h"

extern "C"
{
#include "zend_compile.h"
#include "zend_execute.h"
#include "ext/standard/info.h"
}

static void openrasp_pzval_unlock_func(zval *z, openrasp_free_op *should_free, int unref);
static void openrasp_pzval_unlock_free_func(zval *z);
static void openrasp_pzval_lock_func(zval *z, openrasp_free_op *should_free);
static int openrasp_binary_assign_op_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS);

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

static int openrasp_qm_assign_handler(ZEND_OPCODE_HANDLER_ARGS)
{
    zend_op *opline = execute_data->opline;
    zval *op1 = NULL;
    openrasp_free_op free_op1 = {0};

    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
        break;
    case IS_VAR:
        op1 = openrasp_get_zval_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
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
        if (op1 && IS_STRING == Z_TYPE_P(op1) && PHP_OPENRASP_POSSIBLE(op1))
        {
            zval *result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;
            Z_STRVAL_P(result) = erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + PHP_OPENRASP_MAGIC_LENGTH);
            PHP_OPENRASP_MARK(result, PHP_OPENRASP_MAGIC_POSSIBLE);
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
    uint tainted = 0;

    result = &OPENRASP_T(OPENRASP_RESULT_VAR(opline)).tmp_var;
    switch (OPENRASP_OP1_TYPE(opline))
    {
    case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
#else
        op1 = openrasp_get_zval_ptr_tmp(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
#endif
        break;

    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
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
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
#else
        op2 = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
#endif
        break;

    case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
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
        ns.insert(0, OPENRASP_TAINT_SEQUENCE(op1));
        ns.insert(ns.length(), OPENRASP_TAINT_SEQUENCE(op2));
    }

    concat_function(result, op1, op2 TSRMLS_CC);
    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result))
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

// static int openrasp_binary_assign_op_helper(int (*binary_op)(zval *result, zval *op1, zval *op2 TSRMLS_DC), ZEND_OPCODE_HANDLER_ARGS)
// {
//     zend_op *opline = execute_data->opline;
//     openrasp_free_op free_op1 = {0}, free_op2 = {0}, free_op_data2 = {0}, free_op_data1 = {0};
//     zval **var_ptr = NULL, **object_ptr = NULL, *value = NULL;
//     zend_bool increment_opline = 0;
//     uint tainted = 0;

//     switch (opline->extended_value)
//     {
//         //     case ZEND_ASSIGN_OBJ:
//         //         return php_taint_binary_assign_op_obj_helper(binary_op, ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
//         //         break;
//         //     case ZEND_ASSIGN_DIM:
//         //     {
//         //         switch (TAINT_OP1_TYPE(opline))
//         //         {
//         //         case IS_VAR:
//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//         //             object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
//         // #else
//         //             object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
//         // #endif
//         //             if (object_ptr && !(free_op1.var != NULL))
//         //             {
//         //                 Z_ADDREF_P(*object_ptr); /* undo the effect of get_obj_zval_ptr_ptr() */
//         //             }
//         //             break;
//         //         case IS_CV:
//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
//         //             object_ptr = php_taint_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_W TSRMLS_CC);
//         // #else
//         //             object_ptr = php_taint_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W TSRMLS_CC);
//         // #endif
//         //             break;
//         //         case IS_UNUSED:
//         //             object_ptr = php_taint_get_obj_zval_ptr_ptr_unused(TSRMLS_C);
//         //             if (object_ptr)
//         //             {
//         //                 Z_ADDREF_P(*object_ptr); /* undo the effect of get_obj_zval_ptr_ptr() */
//         //             }
//         //             break;
//         //         default:
//         //             /* do nothing */
//         //             break;
//         //         }

//         //         if (object_ptr && Z_TYPE_PP(object_ptr) == IS_OBJECT)
//         //         {
//         //             return php_taint_binary_assign_op_obj_helper(binary_op, ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
//         //         }
//         //         else
//         //         {
//         //             zend_op *op_data = opline + 1;

//         //             zval *dim;

//         //             switch (TAINT_OP2_TYPE(opline))
//         //             {
//         //             case IS_TMP_VAR:
//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//         //                 dim = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
//         // #else
//         //                 dim = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
//         // #endif
//         //                 break;
//         //             case IS_VAR:
//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//         //                 dim = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
//         // #else
//         //                 dim = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
//         // #endif
//         //                 break;
//         //             case IS_CV:
//         //                 dim = php_taint_get_zval_ptr_cv(TAINT_OP2_NODE_PTR(opline), TAINT_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
//         //                 break;
//         //             case IS_CONST:
//         //                 dim = TAINT_OP2_CONSTANT_PTR(opline);
//         //                 break;
//         //             case IS_UNUSED:
//         //                 dim = NULL;
//         //                 break;
//         //             default:
//         //                 /* do nothing */
//         //                 break;
//         //             }

//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
//         //             if (TAINT_OP2_TYPE(opline) == IS_TMP_VAR)
//         //             {
//         //                 php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, 1, BP_VAR_RW TSRMLS_CC);
//         //             }
//         //             else
//         //             {
//         //                 php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, 0, BP_VAR_RW TSRMLS_CC);
//         //             }
//         //             value = php_taint_get_zval_ptr(&op_data->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
//         //             var_ptr = php_taint_get_zval_ptr_ptr(&op_data->op2, execute_data->Ts, &free_op_data2, BP_VAR_RW TSRMLS_CC);
//         // #else
//         // #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//         //             php_taint_fetch_dimension_address(&TAINT_T((opline + 1)->op2.var), object_ptr, dim, IS_TMP_VAR, BP_VAR_RW TSRMLS_CC);
//         //             value = php_taint_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data, &free_op_data1, BP_VAR_R TSRMLS_CC);
//         //             var_ptr = php_taint_get_zval_ptr_ptr_var((opline + 1)->op2.var, execute_data, &free_op_data2 TSRMLS_CC);
//         // #else
//         //             php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, TAINT_OP2_TYPE(opline), BP_VAR_RW TSRMLS_CC);
//         //             value = php_taint_get_zval_ptr((opline + 1)->op1_type, &(opline + 1)->op1, execute_data->Ts, &free_op_data1, BP_VAR_R TSRMLS_CC);
//         //             var_ptr = php_taint_get_zval_ptr_ptr_var((opline + 1)->op2.var, execute_data->Ts, &free_op_data2 TSRMLS_CC);
//         // #endif
//         // #endif
//         //             increment_opline = 1;
//         //         }
//         //     }
//         //     break;
//     default:
//         switch (OPENRASP_OP2_TYPE(opline))
//         {
//         case IS_TMP_VAR:
// #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//             value = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
// #else
//             value = openrasp_get_zval_ptr_tmp(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
// #endif
//             break;
//         case IS_VAR:
// #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//             value = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data, &free_op2 TSRMLS_CC);
// #else
//             value = openrasp_get_zval_ptr_var(OPENRASP_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2 TSRMLS_CC);
// #endif
//             break;
//         case IS_CV:
//             value = openrasp_get_zval_ptr_cv(OPENRASP_OP2_NODE_PTR(opline), OPENRASP_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R) TSRMLS_CC);
//             break;
//         case IS_CONST:
//             value = OPENRASP_OP2_CONSTANT_PTR(opline);
//             break;
//         case IS_UNUSED:
//             value = NULL;
//             break;
//         default:
//             /* do nothing */
//             break;
//         }

//         switch (OPENRASP_OP1_TYPE(opline))
//         {
//         case IS_VAR:
// #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
//             var_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data, &free_op1 TSRMLS_CC);
// #else
//             var_ptr = openrasp_get_zval_ptr_ptr_var(OPENRASP_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1 TSRMLS_CC);
// #endif
//             break;
//         case IS_CV:
// #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
//             var_ptr = openrasp_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_RW TSRMLS_CC);
// #else
//             var_ptr = openrasp_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_RW TSRMLS_CC);
// #endif
//             break;
//         case IS_UNUSED:
//             var_ptr = NULL;
//             break;
//         default:
//             /* do nothing */
//             break;
//         }
//         /* do nothing */
//         break;
//     }

//     if (!var_ptr)
//     {
//         zend_error(E_ERROR, "Cannot use assign-op operators with overloaded objects nor string offsets");
//         return 0;
//     }

//     if (*var_ptr == EG(error_zval_ptr))
//     {
//         if (OPENRASP_RETURN_VALUE_USED(opline))
//         {
//             OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr = &EG(uninitialized_zval_ptr);
//             Z_ADDREF_P(*OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr);
//             OPENRASP_AI_USE_PTR(OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var);
//         }

//         switch (OPENRASP_OP2_TYPE(opline))
//         {
//         case IS_TMP_VAR:
//             zval_dtor(free_op2.var);
//             break;
//         case IS_VAR:
//             if (free_op2.var)
//             {
//                 zval_ptr_dtor(&free_op2.var);
//             };
//             break;
//         case IS_CV:
//         case IS_CONST:
//         case IS_UNUSED:
//         default:
//             /* do nothing */
//             break;
//         }

//         if (IS_VAR == OPENRASP_OP1_TYPE(opline) && free_op1.var)
//         {
//             zval_ptr_dtor(&free_op1.var);
//         };
//         if (increment_opline)
//         {
//             execute_data->opline++;
//         }
//         execute_data->opline++;
//     }

//     if ((*var_ptr && IS_STRING == Z_TYPE_PP(var_ptr) && Z_STRLEN_PP(var_ptr) && OPENRASP_TAINT_POSSIBLE(*var_ptr)) || (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && OPENRASP_TAINT_POSSIBLE(value)))
//     {
//         tainted = 1;
//     }

//     SEPARATE_ZVAL_IF_NOT_REF(var_ptr);

//     if (Z_TYPE_PP(var_ptr) == IS_OBJECT && Z_OBJ_HANDLER_PP(var_ptr, get) && Z_OBJ_HANDLER_PP(var_ptr, set))
//     {
//         /* proxy object */
//         zval *objval = Z_OBJ_HANDLER_PP(var_ptr, get)(*var_ptr TSRMLS_CC);
//         Z_ADDREF_P(objval);
//         if ((objval && IS_STRING == Z_TYPE_P(objval) && Z_STRLEN_P(objval) && OPENRASP_TAINT_POSSIBLE(objval)) || (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && OPENRASP_TAINT_POSSIBLE(value)))
//         {
//             tainted = 1;
//         }
//         binary_op(objval, objval, value TSRMLS_CC);
//         if (tainted && IS_STRING == Z_TYPE_P(objval) && Z_STRLEN_P(objval))
//         {
//             Z_STRVAL_P(objval) = erealloc(Z_STRVAL_P(objval), Z_STRLEN_P(objval) + 1 + PHP_TAINT_MAGIC_LENGTH);
//             OPENRASP_TAINT_MARK(objval, PHP_TAINT_MAGIC_POSSIBLE);
//         }

//         Z_OBJ_HANDLER_PP(var_ptr, set)
//         (var_ptr, objval TSRMLS_CC);
//         zval_ptr_dtor(&objval);
//     }
//     else
//     {
//         binary_op(*var_ptr, *var_ptr, value TSRMLS_CC);
//         if (tainted && IS_STRING == Z_TYPE_PP(var_ptr) && Z_STRLEN_PP(var_ptr))
//         {
//             Z_STRVAL_PP(var_ptr) = erealloc(Z_STRVAL_PP(var_ptr), Z_STRLEN_PP(var_ptr) + 1 + PHP_TAINT_MAGIC_LENGTH);
//             OPENRASP_TAINT_MARK(*var_ptr, PHP_TAINT_MAGIC_POSSIBLE);
//         }
//     }

//     if (OPENRASP_RETURN_VALUE_USED(opline))
//     {
//         OPENRASP_T(OPENRASP_RESULT_VAR(opline)).var.ptr_ptr = var_ptr;
//         Z_ADDREF_P(*var_ptr);
//         OPENRASP_AI_USE_PTR(OPENRASP_T(OPENRASP_TAINT_MARKRESULT_VAR(opline)).var);
//     }

//     switch (OPENRASP_TAINT_MARKOP2_TYPE(opline))
//     {
//     case IS_TMP_VAR:
//         zval_dtor(free_op2.var);
//         break;
//     case IS_VAR:
//         if (free_op2.var)
//         {
//             zval_ptr_dtor(&free_op2.var);
//         };
//         break;
//     case IS_CV:
//     case IS_CONST:
//     case IS_UNUSED:
//     default:
//         /* do nothing */
//         break;
//     }

//     if (increment_opline)
//     {
//         execute_data->opline++;
//         openrasp_free_op(free_op_data1);
//         openrasp_free_op_VAR_PTR(free_op_data2);
//     }
//     if (IS_VAR == OPENRASP_TAINT_MARKOP1_TYPE(opline) && free_op1.var)
//     {
//         zval_ptr_dtor(&free_op1.var);
//     };

//     execute_data->opline++;
//     return ZEND_USER_OPCODE_CONTINUE;
// }

void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource TSRMLS_DC)
{
    zval **ppzval;
    HashTable *ht = Z_ARRVAL_P(symbol_table);
    HashPosition pos = {0};

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