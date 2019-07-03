/*
 * Copyright 2017-2019 Baidu Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "openrasp_hook.h"
#include "taint.h"

#define ALIGN_LEFT 0
#define ALIGN_RIGHT 1
#define ADJ_WIDTH 1
#define ADJ_PRECISION 2

static void taint_formatted_print(NodeSequence &ns, int ht, int use_array, int format_offset TSRMLS_DC);
inline static int openrasp_sprintf_getnumber(char *buffer, int *pos);
static inline int php_charmask(unsigned char *input, int len, char *mask TSRMLS_DC);
char *trim_taint(char *c, int len, char *what, int what_len, zval *return_value, int mode TSRMLS_DC);
static void unchanege_taint(zval *arg, zval *return_value TSRMLS_DC);

/**
 * taint 相关hook点
 */
POST_HOOK_FUNCTION(strval, TAINT);
POST_HOOK_FUNCTION(explode, TAINT);
POST_HOOK_FUNCTION(implode, TAINT);
POST_HOOK_FUNCTION(join, TAINT);
POST_HOOK_FUNCTION(trim, TAINT);
POST_HOOK_FUNCTION(ltrim, TAINT);
POST_HOOK_FUNCTION(rtrim, TAINT);
POST_HOOK_FUNCTION(strtolower, TAINT);
POST_HOOK_FUNCTION(strtoupper, TAINT);
#ifdef sprintf
#undef sprintf
#endif
OPENRASP_HOOK_FUNCTION(sprintf, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT TSRMLS_CC);
    static bool processing = false;
    NodeSequence ns;
    if (!type_ignored)
    {
        if (!processing)
        {
            processing = true;
            taint_formatted_print(ns, ht, 0, 0 TSRMLS_CC);
            processing = false;
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored && processing == false)
    {
        if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
        {
            Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(return_value, new NodeSequence(ns));
        }
    }
}
#ifndef sprintf
#define sprintf php_sprintf
#endif

OPENRASP_HOOK_FUNCTION(vsprintf, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT TSRMLS_CC);
    static bool processing = false;
    NodeSequence ns;
    if (!type_ignored)
    {
        if (!processing)
        {
            processing = true;
            taint_formatted_print(ns, ht, 1, 0 TSRMLS_CC);
            processing = false;
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored && processing == false)
    {
        if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
        {
            Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(return_value, new NodeSequence(ns));
        }
    }
}

inline static int openrasp_sprintf_getnumber(char *buffer, int *pos)
{
    char *endptr;
    register long num = strtol(&buffer[*pos], &endptr, 10);
    register int i = 0;

    if (endptr != NULL)
    {
        i = (endptr - &buffer[*pos]);
    }
    *pos += i;

    if (num >= INT_MAX || num < 0)
    {
        return -1;
    }
    else
    {
        return (int)num;
    }
}

static void taint_formatted_print(NodeSequence &ns, int ht, int use_array, int format_offset TSRMLS_DC)
{
    zval ***args, **z_format;
    int argc, inpos = 0, temppos;
    int alignment, currarg, adjusting, argnum, width, precision;
    char *format, padding;
    int always_sign;
    int format_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &argc) == FAILURE)
    {
        return;
    }

    /* verify the number of args */
    if ((use_array && argc != (2 + format_offset)) || (!use_array && argc < (1 + format_offset)))
    {
        efree(args);
        return;
    }

    if (use_array)
    {
        int i = 1;
        zval ***newargs;
        zval **array;

        z_format = args[format_offset];
        array = args[1 + format_offset];

        SEPARATE_ZVAL(array);
        convert_to_array_ex(array);

        argc = 1 + zend_hash_num_elements(Z_ARRVAL_PP(array));
        newargs = (zval ***)safe_emalloc(argc, sizeof(zval *), 0);
        newargs[0] = z_format;

        for (zend_hash_internal_pointer_reset(Z_ARRVAL_PP(array));
             zend_hash_get_current_data(Z_ARRVAL_PP(array), (void **)&newargs[i++]) == SUCCESS;
             zend_hash_move_forward(Z_ARRVAL_PP(array)))
            ;

        efree(args);
        args = newargs;
        format_offset = 0;
    }
    convert_to_string_ex(args[format_offset]);
    if (Z_TYPE_PP(args[format_offset]) == IS_STRING)
    {
        ns = OPENRASP_TAINT_SEQUENCE(*args[format_offset]);
    }
    else
    {
        return;
    }
    format = Z_STRVAL_PP(args[format_offset]);
    format_len = Z_STRLEN_PP(args[format_offset]);
    currarg = 1;
    while (inpos < Z_STRLEN_PP(args[format_offset]))
    {
        int expprec = 0, multiuse = 0;
        zval *tmp;
        if (format[inpos] != '%')
        {
            inpos++;
        }
        else if (format[inpos + 1] == '%')
        {
            ns.erase(inpos, 1);
            inpos += 2;
        }
        else
        {
            int percentage_mark_pos = inpos;
            /* starting a new format specifier, reset variables */
            alignment = ALIGN_RIGHT;
            adjusting = 0;
            padding = ' ';
            always_sign = 0;
            inpos++; /* skip the '%' */
            int modifiers_pos = inpos;
            if (isascii((int)format[inpos]) && !isalpha((int)format[inpos]))
            {
                /* first look for argnum */
                temppos = inpos;
                while (isdigit((int)format[temppos]))
                    temppos++;
                if (format[temppos] == '$')
                {
                    argnum = openrasp_sprintf_getnumber(format, &inpos);

                    if (argnum <= 0)
                    {
                        efree(args);
                        return;
                    }
                    multiuse = 1;
                    inpos++; /* skip the '$' */
                }
                else
                {
                    argnum = currarg++;
                }

                argnum += format_offset;

                modifiers_pos = inpos;
                /* after argnum comes modifiers */
                for (;; inpos++)
                {
                    if (format[inpos] == ' ' || format[inpos] == '0')
                    {
                        padding = format[inpos];
                    }
                    else if (format[inpos] == '-')
                    {
                        alignment = ALIGN_LEFT;
                        /* space padding, the default */
                    }
                    else if (format[inpos] == '+')
                    {
                        always_sign = 1;
                    }
                    else if (format[inpos] == '\'')
                    {
                        padding = format[++inpos];
                    }
                    else
                    {
                        break;
                    }
                }

                /* after modifiers comes width */
                if (isdigit((int)format[inpos]))
                {
                    if ((width = openrasp_sprintf_getnumber(format, &inpos)) < 0)
                    {
                        efree(args);
                        return;
                    }
                    adjusting |= ADJ_WIDTH;
                }
                else
                {
                    width = 0;
                }

                /* after width and argnum comes precision */
                if (format[inpos] == '.')
                {
                    inpos++;
                    if (isdigit((int)format[inpos]))
                    {
                        if ((precision = openrasp_sprintf_getnumber(format, &inpos)) < 0)
                        {
                            efree(args);
                            return;
                        }
                        adjusting |= ADJ_PRECISION;
                        expprec = 1;
                    }
                    else
                    {
                        precision = 0;
                    }
                }
                else
                {
                    precision = 0;
                }
            }
            else
            {
                width = precision = 0;
                argnum = currarg++ + format_offset;
            }

            if (argnum >= argc)
            {
                efree(args);
                return;
            }

            if (format[inpos] == 'l')
            {
                inpos++;
            }
            NodeSequence item_ns;
            if (Z_TYPE_P(*(args[argnum])) == IS_STRING && OPENRASP_TAINT_POSSIBLE(*(args[argnum])))
            {
                item_ns = OPENRASP_TAINT_SEQUENCE(*(args[argnum]));
            }
            /* now we expect to find a type specifier */
            if (multiuse)
            {
                MAKE_STD_ZVAL(tmp);
                *tmp = **(args[argnum]);
                INIT_PZVAL(tmp);
                zval_copy_ctor(tmp);
            }
            else
            {
                SEPARATE_ZVAL(args[argnum]);
                tmp = *(args[argnum]);
            }
            if (format[inpos] == 's' && Z_TYPE_P(tmp) == IS_STRING && item_ns.taintedSize())
            {
                zval *var, var_copy;
                int use_copy;

                zend_make_printable_zval(tmp, &var_copy, &use_copy);
                if (use_copy)
                {
                    var = &var_copy;
                }
                else
                {
                    var = tmp;
                }
                register int npad;
                int copy_len;
                copy_len = (expprec ? MIN(precision, Z_STRLEN_P(var)) : Z_STRLEN_P(var));
                npad = width - copy_len;
                if (npad < 0)
                {
                    npad = 0;
                }
                if (alignment == ALIGN_RIGHT)
                {
                    while (npad-- > 0)
                    {
                        item_ns.insert(0, 1);
                    }
                }
                if (alignment == ALIGN_LEFT)
                {
                    while (npad--)
                    {
                        item_ns.append(1);
                    }
                }
                ns.erase(percentage_mark_pos, inpos - percentage_mark_pos + 1);
                ns.insert(percentage_mark_pos, item_ns);
                if (use_copy)
                {
                    zval_dtor(&var_copy);
                }
            }
            else
            {
                zval function;
                INIT_ZVAL(function);
                ZVAL_STRING(&function, "sprintf", 0);
                zval retval;
                zval *o_format = *args[format_offset];
                zval *n_format = nullptr;
                MAKE_STD_ZVAL(n_format);
                std::string specifier = "%";
                specifier.append(Z_STRVAL_P(o_format) + modifiers_pos, inpos - modifiers_pos + 1);
                ZVAL_STRING(n_format, (char *)specifier.c_str(), 1);
                zval *params[2];
                params[0] = n_format;
                params[1] = tmp;
                if (call_user_function(EG(function_table), nullptr, &function, &retval, 2, params TSRMLS_CC) == SUCCESS &&
                    Z_TYPE(retval) == IS_STRING)
                {
                    ns.erase(percentage_mark_pos, inpos - percentage_mark_pos + 1);
                    ns.insert(percentage_mark_pos, Z_STRLEN(retval));
                    zval_dtor(&retval);
                }
                zval_ptr_dtor(&n_format);
            }
            if (multiuse)
            {
                zval_ptr_dtor(&tmp);
            }
            inpos++;
        }
    }
    efree(args);
}

void post_global_strval_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **arg;

    if (ZEND_NUM_ARGS() != 1 || zend_get_parameters_ex(1, &arg) == FAILURE)
    {
        WRONG_PARAM_COUNT;
    }
    unchanege_taint(*arg, return_value TSRMLS_CC);
}

void post_global_explode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    int size = 0;

    if (Z_TYPE_P(return_value) == IS_ARRAY && (size = zend_hash_num_elements(Z_ARRVAL_P(return_value))) > 0)
    {
        zval *zdelim = nullptr;
        zval *zstr = nullptr;
        long limit = LONG_MAX; /* No limit */

        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &zdelim, &zstr, &limit) == FAILURE)
        {
            return;
        }

        if (limit == 0)
        {
            limit = 1;
        }

        if (Z_TYPE_P(zstr) == IS_STRING && Z_STRLEN_P(zstr) &&
            Z_TYPE_P(zdelim) == IS_STRING && Z_STRLEN_P(zdelim) &&
            OPENRASP_TAINT_POSSIBLE(zstr))
        {
            NodeSequence ns = OPENRASP_TAINT_SEQUENCE(zstr);
            std::string str(Z_STRVAL_P(zstr), Z_STRLEN_P(zstr));
            std::string delim(Z_STRVAL_P(zdelim), Z_STRLEN_P(zdelim));
            size_t start = 0;
            size_t found = 0;
            HashTable *ht = Z_ARRVAL_P(return_value);

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
                if (IS_STRING == Z_TYPE_PP(ele_value) && type == HASH_KEY_IS_LONG)
                {
                    Z_STRVAL_PP(ele_value) = (char *)erealloc(Z_STRVAL_PP(ele_value), Z_STRLEN_PP(ele_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
                    if (idx < size - 1)
                    {
                        found = str.find(delim, start);
                        if (found != std::string::npos)
                        {
                            OPENRASP_TAINT_MARK(*ele_value, new NodeSequence(ns.sub(start, found - start)));
                            start = found + delim.length();
                        }
                    }
                    else if (idx == size - 1)
                    {
                        if (limit > 0)
                        {
                            OPENRASP_TAINT_MARK(*ele_value, new NodeSequence(ns.sub(start)));
                        }
                        else
                        {
                            found = str.find(delim, start);
                            if (found != std::string::npos)
                            {
                                OPENRASP_TAINT_MARK(*ele_value, new NodeSequence(ns.sub(start, found - start)));
                            }
                        }
                    }
                }
            }
        }
    }
}

void post_global_implode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **arg1 = NULL, **arg2 = NULL, *delim, *arr;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|Z", &arg1, &arg2) == FAILURE)
    {
        return;
    }

    if (arg2 == NULL)
    {
        if (Z_TYPE_PP(arg1) != IS_ARRAY)
        {
            return;
        }

        MAKE_STD_ZVAL(delim);
        ZVAL_STRINGL(delim, "", sizeof("") - 1, 0);
        SEPARATE_ZVAL(arg1);
        arr = *arg1;
    }
    else
    {
        if (Z_TYPE_PP(arg1) == IS_ARRAY)
        {
            arr = *arg1;
            convert_to_string_ex(arg2);
            delim = *arg2;
        }
        else if (Z_TYPE_PP(arg2) == IS_ARRAY)
        {
            arr = *arg2;
            convert_to_string_ex(arg1);
            delim = *arg1;
        }
        else
        {
            return;
        }
    }
    NodeSequence ns;
    {
        zval **tmp;
        HashPosition pos;
        int numelems, i = 0;
        zval tmp_val;
        int str_len;

        numelems = zend_hash_num_elements(Z_ARRVAL_P(arr));

        if (numelems == 0)
        {
            return;
        }

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(arr), &pos);

        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(arr), (void **)&tmp, &pos) == SUCCESS)
        {
            switch ((*tmp)->type)
            {
            case IS_STRING:
                ns.append(OPENRASP_TAINT_SEQUENCE(*tmp));
                break;

            case IS_LONG:
            {
                char stmp[MAX_LENGTH_OF_LONG + 1];
                str_len = slprintf(stmp, sizeof(stmp), "%ld", Z_LVAL_PP(tmp));
                ns.append(str_len);
            }
            break;

            case IS_BOOL:
                if (Z_LVAL_PP(tmp) == 1)
                {
                    ns.append(1);
                }
                break;

            case IS_NULL:
                break;

            case IS_DOUBLE:
            {
                char *stmp;
                str_len = spprintf(&stmp, 0, "%.*G", (int)EG(precision), Z_DVAL_PP(tmp));
                ns.append(str_len);
                efree(stmp);
            }
            break;

            case IS_OBJECT:
            {
                int copy;
                zval expr;
                zend_make_printable_zval(*tmp, &expr, &copy);
                ns.append(OPENRASP_TAINT_SEQUENCE(&expr));
                if (copy)
                {
                    zval_dtor(&expr);
                }
            }
            break;

            default:
                tmp_val = **tmp;
                zval_copy_ctor(&tmp_val);
                convert_to_string(&tmp_val);
                ns.append(OPENRASP_TAINT_SEQUENCE(&tmp_val));
                zval_dtor(&tmp_val);
                break;
            }

            if (++i != numelems)
            {
                ns.append(OPENRASP_TAINT_SEQUENCE(delim));
            }
            zend_hash_move_forward_ex(Z_ARRVAL_P(arr), &pos);
        }
    }

    if (arg2 == NULL)
    {
        FREE_ZVAL(delim);
    }

    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
    {
        Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(return_value, new NodeSequence(ns));
    }
}

void post_global_join_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    return post_global_implode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static inline int php_charmask(unsigned char *input, int len, char *mask TSRMLS_DC)
{
    unsigned char *end;
    unsigned char c;
    int result = SUCCESS;

    memset(mask, 0, 256);
    for (end = input + len; input < end; input++)
    {
        c = *input;
        if ((input + 3 < end) && input[1] == '.' && input[2] == '.' && input[3] >= c)
        {
            memset(mask + c, 1, input[3] - c + 1);
            input += 3;
        }
        else if ((input + 1 < end) && input[0] == '.' && input[1] == '.')
        {
            /* Error, try to be as helpful as possible:
			   (a range ending/starting with '.' won't be captured here) */
            if (end - len >= input)
            { /* there was no 'left' char */
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid '..'-range, no character to the left of '..'");
                result = FAILURE;
                continue;
            }
            if (input + 2 >= end)
            { /* there is no 'right' char */
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid '..'-range, no character to the right of '..'");
                result = FAILURE;
                continue;
            }
            if (input[-1] > input[2])
            { /* wrong order */
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid '..'-range, '..'-range needs to be incrementing");
                result = FAILURE;
                continue;
            }
            /* FIXME: better error (a..b..c is the only left possibility?) */
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid '..'-range");
            result = FAILURE;
            continue;
        }
        else
        {
            mask[c] = 1;
        }
    }
    return result;
}

void trim_taint(zval *zstr, char *what, int what_len, zval *return_value, int mode TSRMLS_DC)
{
    if (Z_TYPE_P(zstr) == IS_STRING && Z_STRLEN_P(zstr) && OPENRASP_TAINT_POSSIBLE(zstr))
    {
        char *c = Z_STRVAL_P(zstr);
        int len = Z_STRLEN_P(zstr);
        NodeSequence ns = OPENRASP_TAINT_SEQUENCE(zstr);
        register int i;
        char mask[256];

        if (what)
        {
            php_charmask((unsigned char *)what, what_len, mask TSRMLS_CC);
        }
        else
        {
            php_charmask((unsigned char *)" \n\r\t\v\0", 6, mask TSRMLS_CC);
        }

        if (mode & 1)
        {
            for (i = 0; i < len; i++)
            {
                if (mask[(unsigned char)c[i]])
                {
                    ns.erase(0, 1);
                }
                else
                {
                    break;
                }
            }
        }
        if (mode & 2)
        {
            for (i = len - 1; i >= 0; i--)
            {
                if (mask[(unsigned char)c[i]])
                {
                    ns.erase(ns.length() - 1);
                }
                else
                {
                    break;
                }
            }
        }

        if (return_value &&
            ns.taintedSize() &&
            IS_STRING == Z_TYPE_P(return_value) &&
            Z_STRLEN_P(return_value) &&
            ns.length() == Z_STRLEN_P(return_value))
        {
            Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
            OPENRASP_TAINT_MARK(return_value, new NodeSequence(ns));
        }
    }
}

void post_global_trim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *zstr = nullptr;
    char *what = nullptr;
    int what_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|s", &zstr, &what, &what_len) == FAILURE)
    {
        return;
    }
    trim_taint(zstr, what, what_len, return_value, 3 TSRMLS_CC);
}

void post_global_ltrim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *zstr = nullptr;
    char *what = nullptr;
    int what_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|s", &zstr, &what, &what_len) == FAILURE)
    {
        return;
    }
    trim_taint(zstr, what, what_len, return_value, 1 TSRMLS_CC);
}

void post_global_rtrim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *zstr = nullptr;
    char *what = nullptr;
    int what_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|s", &zstr, &what, &what_len) == FAILURE)
    {
        return;
    }
    trim_taint(zstr, what, what_len, return_value, 2 TSRMLS_CC);
}

static void unchanege_taint(zval *arg, zval *return_value TSRMLS_DC)
{
    if (Z_TYPE_P(arg) == IS_STRING &&
        OPENRASP_TAINT_POSSIBLE(arg) &&
        IS_STRING == Z_TYPE_P(return_value) &&
        Z_STRLEN_P(return_value))
    {
        Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(return_value, new NodeSequence(OPENRASP_TAINT_SEQUENCE(arg)));
    }
}

void post_global_strtolower_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *arg;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE)
    {
        return;
    }
    unchanege_taint(arg, return_value TSRMLS_CC);
}

void post_global_strtoupper_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *arg;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE)
    {
        return;
    }
    unchanege_taint(arg, return_value TSRMLS_CC);
}