#include "openrasp_hook.h"
#include "taint.h"

extern "C"
{
#include "zend_compile.h"
#include "zend_execute.h"
#include "ext/standard/info.h"
}

using taint::TaintNode;

static int openrasp_make_real_object(zval *object)
{
    if (UNEXPECTED(Z_TYPE_P(object) != IS_OBJECT))
    {
        if (EXPECTED(Z_TYPE_P(object) <= IS_FALSE))
        {
            /* nothing to destroy */
        }
        else if (EXPECTED((Z_TYPE_P(object) == IS_STRING && Z_STRLEN_P(object) == 0)))
        {
            zval_ptr_dtor_nogc(object);
        }
        else
        {
            return 0;
        }
        object_init(object);
        zend_error(E_WARNING, "Creating default object from empty value");
    }
    return 1;
}

static zend_long openrasp_check_string_offset(zval *dim, int type)
{
    zend_long offset;

try_again:
    if (UNEXPECTED(Z_TYPE_P(dim) != IS_LONG))
    {
        switch (Z_TYPE_P(dim))
        {
        case IS_STRING:
            if (IS_LONG == is_numeric_string(Z_STRVAL_P(dim), Z_STRLEN_P(dim), nullptr, nullptr, -1))
            {
                break;
            }
            if (type != BP_VAR_UNSET)
            {
                zend_error(E_WARNING, "Illegal string offset '%s'", Z_STRVAL_P(dim));
            }
            break;
        case IS_DOUBLE:
        case IS_NULL:
        case IS_FALSE:
        case IS_TRUE:
            zend_error(E_NOTICE, "String offset cast occurred");
            break;
        case IS_REFERENCE:
            dim = Z_REFVAL_P(dim);
            goto try_again;
        default:
            zend_error(E_WARNING, "Illegal offset type");
            break;
        }

        offset = zval_get_long(dim);
    }
    else
    {
        offset = Z_LVAL_P(dim);
    }

    return offset;
}

static zval *openrasp_fetch_dimension_address_inner(HashTable *ht, const zval *dim, int dim_type, int type)
{
    zval *retval;
    zend_string *offset_key;
    zend_ulong hval;

try_again:
    if (EXPECTED(Z_TYPE_P(dim) == IS_LONG))
    {
        hval = Z_LVAL_P(dim);
    num_index:
        retval = zend_hash_index_find(ht, hval);
        if (retval == nullptr)
        {
            switch (type)
            {
            case BP_VAR_R:
                zend_error(E_NOTICE, "Undefined offset: " ZEND_LONG_FMT, hval);
                /* break missing intentionally */
            case BP_VAR_UNSET:
            case BP_VAR_IS:
                retval = &EG(uninitialized_zval);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined offset: " ZEND_LONG_FMT, hval);
                /* break missing intentionally */
            case BP_VAR_W:
                retval = zend_hash_index_add_new(ht, hval, &EG(uninitialized_zval));
                break;
            }
        }
    }
    else if (EXPECTED(Z_TYPE_P(dim) == IS_STRING))
    {
        offset_key = Z_STR_P(dim);
        if (dim_type != IS_CONST)
        {
            if (ZEND_HANDLE_NUMERIC(offset_key, hval))
            {
                goto num_index;
            }
        }
    str_index:
        retval = zend_hash_find(ht, offset_key);
        if (retval)
        {
            /* support for $GLOBALS[...] */
            if (UNEXPECTED(Z_TYPE_P(retval) == IS_INDIRECT))
            {
                retval = Z_INDIRECT_P(retval);
                if (UNEXPECTED(Z_TYPE_P(retval) == IS_UNDEF))
                {
                    switch (type)
                    {
                    case BP_VAR_R:
                        zend_error(E_NOTICE, "Undefined index: %s", ZSTR_VAL(offset_key));
                        /* break missing intentionally */
                    case BP_VAR_UNSET:
                    case BP_VAR_IS:
                        retval = &EG(uninitialized_zval);
                        break;
                    case BP_VAR_RW:
                        zend_error(E_NOTICE, "Undefined index: %s", ZSTR_VAL(offset_key));
                        /* break missing intentionally */
                    case BP_VAR_W:
                        ZVAL_NULL(retval);
                        break;
                    }
                }
            }
        }
        else
        {
            switch (type)
            {
            case BP_VAR_R:
                zend_error(E_NOTICE, "Undefined index: %s", ZSTR_VAL(offset_key));
                /* break missing intentionally */
            case BP_VAR_UNSET:
            case BP_VAR_IS:
                retval = &EG(uninitialized_zval);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined index: %s", ZSTR_VAL(offset_key));
                /* break missing intentionally */
            case BP_VAR_W:
                retval = zend_hash_add_new(ht, offset_key, &EG(uninitialized_zval));
                break;
            }
        }
    }
    else
    {
        switch (Z_TYPE_P(dim))
        {
        case IS_NULL:
            offset_key = ZSTR_EMPTY_ALLOC();
            goto str_index;
        case IS_DOUBLE:
            hval = zend_dval_to_lval(Z_DVAL_P(dim));
            goto num_index;
        case IS_RESOURCE:
            zend_error(E_NOTICE, "Resource ID#%pd used as offset, casting to integer (%pd)", Z_RES_HANDLE_P(dim), Z_RES_HANDLE_P(dim));
            hval = Z_RES_HANDLE_P(dim);
            goto num_index;
        case IS_FALSE:
            hval = 0;
            goto num_index;
        case IS_TRUE:
            hval = 1;
            goto num_index;
        case IS_REFERENCE:
            dim = Z_REFVAL_P(dim);
            goto try_again;
        default:
            zend_error(E_WARNING, "Illegal offset type");
            retval = (type == BP_VAR_W || type == BP_VAR_RW) ?
#if PHP_VERSION_ID < 70100
                                                             &EG(error_zval)
#else
                                                             nullptr
#endif
                                                             : &EG(uninitialized_zval);
        }
    }
    return retval;
}

static void openrasp_fetch_dimension_address(zval *result, zval *container, zval *dim, int dim_type, int type)
{
    zval *retval;

    if (EXPECTED(Z_TYPE_P(container) == IS_ARRAY))
    {
    try_array:
        SEPARATE_ARRAY(container);
    fetch_from_array:
        if (dim == nullptr)
        {
            retval = zend_hash_next_index_insert(Z_ARRVAL_P(container), &EG(uninitialized_zval));
            if (UNEXPECTED(retval == nullptr))
            {
                zend_error(E_WARNING, "Cannot add element to the array as the next element is already occupied");
#if PHP_VERSION_ID < 70100
                retval = &EG(error_zval);
#else
                ZVAL_ERROR(result);
                return;
#endif
            }
        }
        else
        {
            retval = openrasp_fetch_dimension_address_inner(Z_ARRVAL_P(container), dim, dim_type, type);
        }
        ZVAL_INDIRECT(result, retval);
        return;
    }
    else if (EXPECTED(Z_TYPE_P(container) == IS_REFERENCE))
    {
        container = Z_REFVAL_P(container);
        if (EXPECTED(Z_TYPE_P(container) == IS_ARRAY))
        {
            goto try_array;
        }
    }
    if (EXPECTED(Z_TYPE_P(container) == IS_STRING))
    {
        if (type != BP_VAR_UNSET && UNEXPECTED(Z_STRLEN_P(container) == 0))
        {
            zval_ptr_dtor_nogc(container);
        convert_to_array:
            ZVAL_NEW_ARR(container);
            zend_hash_init(Z_ARRVAL_P(container), 8, nullptr, ZVAL_PTR_DTOR, 0);
            goto fetch_from_array;
        }

        if (dim == nullptr)
        {
            zend_throw_error(nullptr, "[] operator not supported for strings");
#if PHP_VERSION_ID < 70100
            ZVAL_INDIRECT(result, &EG(error_zval));
#else
            ZVAL_ERROR(result);
#endif
        }
        else
        {
            openrasp_check_string_offset(dim, type);
#if PHP_VERSION_ID < 70100
            ZVAL_INDIRECT(result, nullptr); /* wrong string offset */
#else
            ZVAL_ERROR(result);
#endif
        }
    }
    else if (EXPECTED(Z_TYPE_P(container) == IS_OBJECT))
    {
        if (!Z_OBJ_HT_P(container)->read_dimension)
        {
            zend_throw_error(nullptr, "Cannot use object as array");
#if PHP_VERSION_ID < 70100
            retval = &EG(error_zval);
#else
            ZVAL_ERROR(result);
#endif
        }
        else
        {
            retval = Z_OBJ_HT_P(container)->read_dimension(container, dim, type, result);

            if (UNEXPECTED(retval == &EG(uninitialized_zval)))
            {
                zend_class_entry *ce = Z_OBJCE_P(container);

                ZVAL_NULL(result);
                zend_error(E_NOTICE, "Indirect modification of overloaded element of %s has no effect", ZSTR_VAL(ce->name));
            }
            else if (EXPECTED(retval && Z_TYPE_P(retval) != IS_UNDEF))
            {
                if (!Z_ISREF_P(retval))
                {
                    if (Z_REFCOUNTED_P(retval) &&
                        Z_REFCOUNT_P(retval) > 1)
                    {
                        if (Z_TYPE_P(retval) != IS_OBJECT)
                        {
                            Z_DELREF_P(retval);
                            ZVAL_DUP(result, retval);
                            retval = result;
                        }
                        else
                        {
                            ZVAL_COPY_VALUE(result, retval);
                            retval = result;
                        }
                    }
                    if (Z_TYPE_P(retval) != IS_OBJECT)
                    {
                        zend_class_entry *ce = Z_OBJCE_P(container);
                        zend_error(E_NOTICE, "Indirect modification of overloaded element of %s has no effect", ZSTR_VAL(ce->name));
                    }
                }
                else if (UNEXPECTED(Z_REFCOUNT_P(retval) == 1))
                {
                    ZVAL_UNREF(retval);
                }
                if (result != retval)
                {
                    ZVAL_INDIRECT(result, retval);
                }
            }
            else
            {
#if PHP_VERSION_ID < 70100
                ZVAL_INDIRECT(result, &EG(error_zval));
#else
                ZVAL_ERROR(result);
#endif
            }
        }
    }
    else if (EXPECTED(Z_TYPE_P(container) <= IS_FALSE))
    {
        if (UNEXPECTED(OPENRASP_ISERR(container)))
        {
#if PHP_VERSION_ID < 70100
            ZVAL_INDIRECT(result, &EG(error_zval));
#else
            ZVAL_ERROR(result);
#endif
        }
        else if (type != BP_VAR_UNSET)
        {
            goto convert_to_array;
        }
        else
        {
            /* for read-mode only */
            ZVAL_NULL(result);
        }
    }
    else
    {
        if (type == BP_VAR_UNSET)
        {
            zend_error(E_WARNING, "Cannot unset offset in a non-array variable");
            ZVAL_NULL(result);
        }
        else
        {
            zend_error(E_WARNING, "Cannot use a scalar value as an array");
#if PHP_VERSION_ID < 70100
            ZVAL_INDIRECT(result, &EG(error_zval));
#else
            ZVAL_ERROR(result);
#endif
        }
    }
}

static zval *openrasp_get_zval_ptr_tmpvar(zend_execute_data *execute_data, uint32_t var, zend_free_op *should_free)
{
    zval *ret = EX_VAR(var);

    if (should_free)
    {
        *should_free = ret;
    }
    ZVAL_DEREF(ret);

    return ret;
}

#ifndef CV_DEF_OF
#define CV_DEF_OF(i) (EX(func)->op_array.vars[i])
#endif

static zval *openrasp_get_zval_ptr_cv(zend_execute_data *execute_data, uint32_t var, int type, int force_ret)
{
    zval *ret = EX_VAR(var);

    if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF))
    {
        if (force_ret)
        {
            switch (type)
            {
            case BP_VAR_R:
            case BP_VAR_UNSET:
                zend_error(E_NOTICE, "Undefined variable: %s", ZSTR_VAL(CV_DEF_OF(EX_VAR_TO_NUM(var))));
            case BP_VAR_IS:
                ret = &EG(uninitialized_zval);
                break;
            case BP_VAR_RW:
                zend_error(E_NOTICE, "Undefined variable: %s", ZSTR_VAL(CV_DEF_OF(EX_VAR_TO_NUM(var))));
            case BP_VAR_W:
                ZVAL_NULL(ret);
                break;
            }
        }
        else
        {
            return nullptr;
        }
    }
    else
    {
        ZVAL_DEREF(ret);
    }
    return ret;
}

static zval *openrasp_get_zval_ptr(zend_execute_data *execute_data, int op_type, znode_op op, openrasp_free_op *should_free, int type, int force_ret)
{
    if (op_type & (IS_TMP_VAR | IS_VAR))
    {
        return openrasp_get_zval_ptr_tmpvar(execute_data, op.var, should_free);
    }
    else
    {
        *should_free = nullptr;
        if (op_type == IS_CONST)
        {
            return EX_CONSTANT(op);
        }
        else if (op_type == IS_CV)
        {
            return openrasp_get_zval_ptr_cv(execute_data, op.var, type, force_ret);
        }
        else
        {
            return nullptr;
        }
    }
}

static zval *openrasp_get_zval_ptr_ptr_var(zend_execute_data *execute_data, uint32_t var, zend_free_op *should_free)
{
    zval *ret = EX_VAR(var);

    if (EXPECTED(Z_TYPE_P(ret) == IS_INDIRECT))
    {
        *should_free = nullptr;
        ret = Z_INDIRECT_P(ret);
    }
    else
    {
        *should_free = ret;
    }
    return ret;
}

static zval *openrasp_get_zval_ptr_ptr(zend_execute_data *execute_data, int op_type, znode_op op, openrasp_free_op *should_free, int type)
{
    if (op_type == IS_CV)
    {
        *should_free = nullptr;
        return openrasp_get_zval_ptr_cv(execute_data, op.var, type, 1);
    }
    else if (op_type == IS_VAR)
    {
        ZEND_ASSERT(op_type == IS_VAR);
        return openrasp_get_zval_ptr_ptr_var(execute_data, op.var, should_free);
    }
    else if (op_type == IS_UNUSED)
    {
        *should_free = nullptr;
        return &EX(This);
    }
    else
    {
        ZEND_ASSERT(0);
    }
}

void openrasp_taint_mark(zval *zv, NodeSequence *ptr)
{
    size_t origin_length = Z_STRLEN_P(zv);
    Z_STR_P(zv) = zend_string_realloc(Z_STR_P(zv), Z_STRLEN_P(zv) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH, 0);
    Z_STRLEN_P(zv) = origin_length;
    *((NodeSequence **)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) = (ptr);
    *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + OPENRASP_TAINT_POINTER_LENGTH + 1)) = (OPENRASP_TAINT_MAGIC_POSSIBLE);
    OPENRASP_G(sequenceManager).registerSequence(ptr);
}

bool openrasp_taint_possible(zval *zv)
{
    return nullptr != zv &&
           Z_TYPE_P(zv) == IS_STRING &&
           Z_STRLEN_P(zv) &&
           *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + OPENRASP_TAINT_POINTER_LENGTH + 1)) == OPENRASP_TAINT_MAGIC_POSSIBLE;
}

bool openrasp_taint_possible(zend_string *zs)
{
    return nullptr != zs &&
           ZSTR_LEN(zs) &&
           *((unsigned *)(ZSTR_VAL(zs) + ZSTR_LEN(zs) + OPENRASP_TAINT_POINTER_LENGTH + 1)) == OPENRASP_TAINT_MAGIC_POSSIBLE;
}

NodeSequence openrasp_taint_sequence(zval *zv)
{
    return openrasp_taint_possible(zv)
               ? **((NodeSequence **)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1))
               : NodeSequence(Z_TYPE_P(zv) == IS_STRING ? Z_STRLEN_P(zv) : 0);
}

NodeSequence openrasp_taint_sequence(zend_string *zs)
{
    return openrasp_taint_possible(zs)
               ? **((NodeSequence **)(ZSTR_VAL(zs) + ZSTR_LEN(zs) + 1))
               : NodeSequence(ZSTR_LEN(zs));
}

static int openrasp_binary_assign_op_helper(binary_op_type binary_op, zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *var_ptr, *value;
    openrasp_free_op free_op1, free_op2;

    value = openrasp_get_zval_ptr(execute_data, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
    var_ptr = openrasp_get_zval_ptr_ptr(execute_data, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);

    if (opline->op1_type == IS_VAR)
    {
        if (var_ptr == NULL || OPENRASP_ISERR(var_ptr))
        {
            return ZEND_USER_OPCODE_DISPATCH;
        }
    }

    NodeSequence ns;
    if (openrasp_taint_possible(var_ptr) ||
        openrasp_taint_possible(value))
    {
        ns.append(openrasp_taint_sequence(var_ptr));
        ns.append(openrasp_taint_sequence(value));
    }

    SEPARATE_ZVAL_NOREF(var_ptr);

    binary_op(var_ptr, var_ptr, value);

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(var_ptr) && Z_STRLEN_P(var_ptr) == ns.length())
    {
        openrasp_taint_mark(var_ptr, new NodeSequence(ns));
    }

    if (OPENRASP_RET_USED(opline))
    {
        ZVAL_COPY(EX_VAR(opline->result.var), var_ptr);
    }

    if ((OPENRASP_OP1_TYPE(opline) & (IS_VAR | IS_TMP_VAR)) && free_op1)
    {
        zval_ptr_dtor_nogc(free_op1);
    }

    if ((OPENRASP_OP2_TYPE(opline) & (IS_VAR | IS_TMP_VAR)) && free_op2)
    {
        zval_ptr_dtor_nogc(free_op2);
    }

    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

static void openrasp_binary_assign_op_obj_dim(zval *object, zval *property, zval *value, zval *retval, binary_op_type binary_op) /* {{{ */
{
    zval *z;
    zval rv, res;

    if (Z_OBJ_HT_P(object)->read_dimension &&
        (z = Z_OBJ_HT_P(object)->read_dimension(object, property, BP_VAR_R, &rv)) != NULL)
    {

        if (Z_TYPE_P(z) == IS_OBJECT && Z_OBJ_HT_P(z)->get)
        {
            zval rv2;
            zval *value = Z_OBJ_HT_P(z)->get(z, &rv2);

            if (z == &rv)
            {
                zval_ptr_dtor(&rv);
            }
            ZVAL_COPY_VALUE(z, value);
        }
        zval *z_real_obj_dim = nullptr;
        if (Z_TYPE_P(z) == IS_STRING)
        {
            z_real_obj_dim = z;
        }
        else if (Z_TYPE_P(z) == IS_REFERENCE && IS_STRING == Z_TYPE_P(Z_REFVAL_P(z)))
        {
            z_real_obj_dim = Z_REFVAL_P(z);
        }
        NodeSequence ns;
        if (openrasp_taint_possible(z_real_obj_dim) ||
            openrasp_taint_possible(value))
        {
            ns.append(openrasp_taint_sequence(z_real_obj_dim));
            ns.append(openrasp_taint_sequence(value));
        }

        binary_op(&res, Z_ISREF_P(z) ? Z_REFVAL_P(z) : z, value);
        Z_OBJ_HT_P(object)->write_dimension(object, property, &res);
        if (z == &rv)
        {
            zval_ptr_dtor(&rv);
        }
        if (retval)
        {
            ZVAL_COPY(retval, &res);
        }
        if (ns.taintedSize() && Z_TYPE(res) == IS_STRING && Z_STRLEN(res) == ns.length())
        {
            openrasp_taint_mark(&res, new NodeSequence(ns));
        }
        zval_ptr_dtor(&res);
    }
    else
    {
        zend_error(E_WARNING, "Attempt to assign property of non-object");
        if (retval)
        {
            ZVAL_NULL(retval);
        }
    }
}

static int openrasp_binary_assign_op_dim_helper(binary_op_type binary_op, zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *container, *dim, *var_ptr, *value, rv;
    openrasp_free_op free_op1, free_op2, free_op_data;

    container = openrasp_get_zval_ptr_ptr(execute_data, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);
    if (opline->op1_type == IS_UNUSED && Z_OBJ_P(container) == NULL)
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (opline->op1_type == IS_VAR && container == NULL)
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    dim = openrasp_get_zval_ptr(execute_data, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);

    do
    {
        if (opline->op1_type == IS_UNUSED || Z_TYPE_P(container) == IS_OBJECT)
        {
            value = openrasp_get_zval_ptr(execute_data, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);
            openrasp_binary_assign_op_obj_dim(container, dim, value, EX_VAR(opline->result.var), binary_op);

            if (!OPENRASP_RET_USED(opline))
            {
                zval_ptr_dtor_nogc(EX_VAR(opline->result.var));
            }
            break;
        }

        openrasp_fetch_dimension_address(&rv, container, dim, opline->op2_type, BP_VAR_RW);
        value = openrasp_get_zval_ptr(execute_data, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);
        ZEND_ASSERT(Z_TYPE(rv) == IS_INDIRECT);
        var_ptr = Z_INDIRECT(rv);

        if (var_ptr == NULL)
        {
            zend_throw_error(NULL, "Cannot use assign-op operators with overloaded objects nor string offsets");
            if ((opline->op2_type & (IS_VAR | IS_TMP_VAR)) && free_op2)
            {
                zval_ptr_dtor_nogc(free_op2);
            }
            if (((opline + 1)->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op_data)
            {
                zval_ptr_dtor_nogc(free_op_data);
            }
            if ((opline->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op1)
            {
                zval_ptr_dtor_nogc(free_op1);
            }
            execute_data->opline += 2;
            return ZEND_USER_OPCODE_CONTINUE;
        }

        if (OPENRASP_ISERR(var_ptr))
        {
            if (OPENRASP_RET_USED(opline))
            {
                ZVAL_NULL(EX_VAR(opline->result.var));
            }
        }
        else
        {
            NodeSequence ns;
            if (openrasp_taint_possible(var_ptr) ||
                openrasp_taint_possible(value))
            {
                ns.append(openrasp_taint_sequence(var_ptr));
                ns.append(openrasp_taint_sequence(value));
            }

            ZVAL_DEREF(var_ptr);
            SEPARATE_ZVAL_NOREF(var_ptr);

            binary_op(var_ptr, var_ptr, value);

            if (OPENRASP_RET_USED(opline))
            {
                ZVAL_COPY(EX_VAR(opline->result.var), var_ptr);
            }

            if (ns.taintedSize() && Z_TYPE_P(var_ptr) == IS_STRING && Z_STRLEN_P(var_ptr) == ns.length())
            {
                openrasp_taint_mark(var_ptr, new NodeSequence(ns));
            }
        }
    } while (0);

    if ((opline->op2_type & (IS_VAR | IS_TMP_VAR)) && free_op2)
    {
        zval_ptr_dtor_nogc(free_op2);
    }
    if (((opline + 1)->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op_data)
    {
        zval_ptr_dtor_nogc(free_op_data);
    }
    if ((opline->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op1)
    {
        zval_ptr_dtor_nogc(free_op1);
    }
    execute_data->opline += 2;

    return ZEND_USER_OPCODE_CONTINUE;
}

static void openrasp_assign_op_overloaded_property(zval *object, zval *property, void **cache_slot, zval *value, binary_op_type binary_op, zval *result)
{
    zval *z;
    zval rv, obj;
    zval *zptr;

    ZVAL_OBJ(&obj, Z_OBJ_P(object));
    Z_ADDREF(obj);
    if (Z_OBJ_HT(obj)->read_property &&
        (z = Z_OBJ_HT(obj)->read_property(&obj, property, BP_VAR_R, cache_slot, &rv)) != NULL)
    {
        if (EG(exception))
        {
            OBJ_RELEASE(Z_OBJ(obj));
            return;
        }
        if (Z_TYPE_P(z) == IS_OBJECT && Z_OBJ_HT_P(z)->get)
        {
            zval rv2;
            zval *value = Z_OBJ_HT_P(z)->get(z, &rv2);

            if (z == &rv)
            {
                zval_ptr_dtor(&rv);
            }
            ZVAL_COPY_VALUE(z, value);
        }
        NodeSequence ns;
        if (openrasp_taint_possible(z) ||
            openrasp_taint_possible(value))
        {
            ns.append(openrasp_taint_sequence(z));
            ns.append(openrasp_taint_sequence(value));
        }

        zptr = z;
        ZVAL_DEREF(z);
        SEPARATE_ZVAL_NOREF(z);

        binary_op(z, z, value);
        Z_OBJ_HT(obj)->write_property(&obj, property, z, cache_slot);
        if (result)
        {
            ZVAL_COPY(result, z);
        }
        if (ns.taintedSize() && Z_TYPE_P(z) == IS_STRING && Z_STRLEN_P(z) == ns.length())
        {
            openrasp_taint_mark(z, new NodeSequence(ns));
        }
        zval_ptr_dtor(zptr);
    }
    else
    {
        zend_error(E_WARNING, "Attempt to assign property of non-object");
        if (result)
        {
            ZVAL_NULL(result);
        }
    }
    OBJ_RELEASE(Z_OBJ(obj));
}

static int openrasp_binary_assign_op_obj_helper(binary_op_type binary_op, zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *object, *property, *var_ptr, *value;
    openrasp_free_op free_op1, free_op2, free_op_data;

    object = openrasp_get_zval_ptr_ptr(execute_data, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);
    if (opline->op1_type == IS_UNUSED && Z_OBJ_P(object) == NULL)
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (opline->op1_type == IS_VAR && object == NULL)
    {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    property = openrasp_get_zval_ptr(execute_data, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);

    do
    {
        if (opline->op1_type == IS_UNUSED || Z_TYPE_P(object) != IS_OBJECT)
        {
            if (!openrasp_make_real_object(object))
            {
                zend_error(E_WARNING, "Attempt to assign property of non-object");
                if (OPENRASP_RET_USED(opline))
                {
                    ZVAL_NULL(EX_VAR(opline->result.var));
                }
                break;
            }
        }

        value = openrasp_get_zval_ptr(execute_data, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);

        if (Z_OBJ_HT_P(object)->get_property_ptr_ptr && (var_ptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property, BP_VAR_RW, NULL)) != NULL)
        {
            NodeSequence ns;
            if (openrasp_taint_possible(var_ptr) ||
                openrasp_taint_possible(value))
            {
                ns.append(openrasp_taint_sequence(var_ptr));
                ns.append(openrasp_taint_sequence(value));
            }
            ZVAL_DEREF(var_ptr);
            SEPARATE_ZVAL_NOREF(var_ptr);

            binary_op(var_ptr, var_ptr, value);
            if (OPENRASP_RET_USED(opline))
            {
                ZVAL_COPY(EX_VAR(opline->result.var), var_ptr);
            }

            if (ns.taintedSize() && Z_TYPE_P(var_ptr) == IS_STRING && Z_STRLEN_P(var_ptr) == ns.length())
            {
                openrasp_taint_mark(var_ptr, new NodeSequence(ns));
            }
        }
        else
        {
            openrasp_assign_op_overloaded_property(object, property, NULL, value, binary_op, EX_VAR(opline->result.var));
            if (!OPENRASP_RET_USED(opline))
            {
                zval_ptr_dtor_nogc(EX_VAR(opline->result.var));
            }
        }
    } while (0);

    if ((opline->op2_type & (IS_VAR | IS_TMP_VAR)) && free_op2)
    {
        zval_ptr_dtor_nogc(free_op2);
    }
    if (((opline + 1)->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op_data)
    {
        zval_ptr_dtor_nogc(free_op_data);
    }
    if ((opline->op1_type & (IS_VAR | IS_TMP_VAR)) && free_op1)
    {
        zval_ptr_dtor_nogc(free_op1);
    }
    execute_data->opline += 2;

    return ZEND_USER_OPCODE_CONTINUE;
}

void str_unchange_taint(zval *src, zval *dest)
{
    if (Z_TYPE_P(src) == IS_STRING &&
        openrasp_taint_possible(src) &&
        IS_STRING == Z_TYPE_P(dest) &&
        Z_STRLEN_P(src) == Z_STRLEN_P(dest))
    {
        openrasp_taint_mark(dest, new NodeSequence(openrasp_taint_sequence(src)));
    }
}

void str_unchange_taint(zend_string *zs_src, zval *dest)
{
    if (openrasp_taint_possible(zs_src) &&
        IS_STRING == Z_TYPE_P(dest) &&
        ZSTR_LEN(zs_src) == Z_STRLEN_P(dest))
    {
        openrasp_taint_mark(dest, new NodeSequence(openrasp_taint_sequence(zs_src)));
    }
}

void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource, std::function<bool(char *key)> filter)
{
    if (Z_TYPE_P(symbol_table) != IS_ARRAY)
    {
        return;
    }
    zval *val;
    zend_string *key;
    zend_ulong idx;
    std::string name;
    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(symbol_table), idx, key, val)
    {
        ZVAL_DEREF(val);
        if (key != nullptr)
        {
            name = std::string(ZSTR_VAL(key));
            if (filter && filter(ZSTR_VAL(key)))
            {
                continue;
            }
        }
        else
        {
            name = std::to_string(idx);
        }

        if (Z_TYPE_P(val) == IS_ARRAY)
        {
            openrasp_taint_mark_strings(val, (varsSource + "['" + name + "']"));
        }
        else if (IS_STRING == Z_TYPE_P(val) && Z_STRLEN_P(val))
        {
            openrasp_taint_mark(val, new NodeSequence(Z_STRLEN_P(val), varsSource, name, true));
        }
    }
    ZEND_HASH_FOREACH_END();
}

int openrasp_concat_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *op1, *op2, *result;
    openrasp_free_op free_op1, free_op2;

    op1 = openrasp_get_zval_ptr(execute_data, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 1);
    op2 = openrasp_get_zval_ptr(execute_data, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);

    result = EX_VAR(opline->result.var);
    NodeSequence ns;
    if (openrasp_taint_possible(op1) || openrasp_taint_possible(op2))
    {
        ns.append(openrasp_taint_sequence(op1));
        ns.append(openrasp_taint_sequence(op2));
    }

    concat_function(result, op1, op2);

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(result) && ns.length() == Z_STRLEN_P(result))
    {
        openrasp_taint_mark(result, new NodeSequence(ns));
    }

    if ((OPENRASP_OP1_TYPE(opline) & (IS_VAR | IS_TMP_VAR)) && free_op1)
    {
        zval_ptr_dtor_nogc(free_op1);
    }

    if ((OPENRASP_OP2_TYPE(opline) & (IS_VAR | IS_TMP_VAR)) && free_op2)
    {
        zval_ptr_dtor_nogc(free_op2);
    }

    execute_data->opline++;

    return ZEND_USER_OPCODE_CONTINUE;
}

int openrasp_assign_concat_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;

    if (EXPECTED(opline->extended_value == 0))
    {
        return openrasp_binary_assign_op_helper(concat_function, execute_data);
    }
    else if (EXPECTED(opline->extended_value == ZEND_ASSIGN_DIM))
    {
        return openrasp_binary_assign_op_dim_helper(concat_function, execute_data);
    }
    else
    {
        return openrasp_binary_assign_op_obj_helper(concat_function, execute_data);
    }
}

int openrasp_repo_end_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *op2, *result;
    openrasp_free_op free_op2;
    zend_string **rope;
    char *target;
    int i;
    size_t len = 0;

    rope = (zend_string **)EX_VAR(opline->op1.var);
    op2 = openrasp_get_zval_ptr(execute_data, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
    result = EX_VAR(opline->result.var);

    rope[opline->extended_value] = zval_get_string(op2);

    NodeSequence ns;
    for (i = 0; i <= opline->extended_value; i++)
    {
        ns.append(openrasp_taint_sequence(rope[i]));
        len += ZSTR_LEN(rope[i]);
    }

    ZVAL_STR(result, zend_string_alloc(len, 0));
    target = Z_STRVAL_P(result);

    for (i = 0; i <= opline->extended_value; i++)
    {
        memcpy(target, ZSTR_VAL(rope[i]), ZSTR_LEN(rope[i]));
        target += ZSTR_LEN(rope[i]);
        zend_string_release(rope[i]);
    }
    *target = '\0';

    if (ns.taintedSize() && Z_STRLEN_P(result) == ns.length())
    {
        openrasp_taint_mark(result, new NodeSequence(ns));
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

    if (IS_STRING == Z_TYPE_P(arg) && openrasp_taint_possible(arg))
    {
        array_init(return_value);
        NodeSequence ns = openrasp_taint_sequence(arg);
        std::list<TaintNode> taintNodes = ns.getSequence();
        for (TaintNode &tn : taintNodes)
        {
            zval z_tainted_node;
            array_init(&z_tainted_node);
            add_assoc_string(&z_tainted_node, "source", (char *)tn.getSource().c_str());
            add_assoc_long(&z_tainted_node, "startIndex", tn.getStartIndex());
            add_assoc_long(&z_tainted_node, "endIndex", tn.getEndIndex());
            add_next_index_zval(return_value, &z_tainted_node);
        }
        return;
    }

    RETURN_FALSE;
}