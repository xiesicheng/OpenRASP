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
#include "utils/string.h"

#define ALIGN_LEFT 0
#define ALIGN_RIGHT 1
#define ADJ_WIDTH 1
#define ADJ_PRECISION 2

#define STR_PAD_LEFT 0
#define STR_PAD_RIGHT 1
#define STR_PAD_BOTH 2

static void taint_formatted_print(NodeSequence &ns, int ht, int use_array, int format_offset TSRMLS_DC);
inline static int openrasp_sprintf_getnumber(char *buffer, int *pos);
static inline int php_charmask(unsigned char *input, int len, char *mask TSRMLS_DC);
void trim_taint(char *c, int len, char *what, int what_len, zval *return_value, int mode TSRMLS_DC);
static void openrasp_str_replace_in_subject(zval *search, zval *replace, zval **subject, zval *result, int case_sensitivity, int *replace_count TSRMLS_DC);
static void openrasp_str_replace_common(OPENRASP_INTERNAL_FUNCTION_PARAMETERS, int case_sensitivity, zval *origin_subject);
static int openrasp_needle_char(zval *needle, char *target TSRMLS_DC);

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
POST_HOOK_FUNCTION(str_pad, TAINT);
POST_HOOK_FUNCTION(strstr, TAINT);
POST_HOOK_FUNCTION(stristr, TAINT);
POST_HOOK_FUNCTION(substr, TAINT);
POST_HOOK_FUNCTION(dirname, TAINT);
POST_HOOK_FUNCTION(basename, TAINT);

OPENRASP_HOOK_FUNCTION(str_replace, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT TSRMLS_CC);
    zval *origin_subject = nullptr;
    if (!type_ignored)
    {
        zval **subject, **search, **replace, **subject_entry, **zcount = NULL;
        char *string_key;
        uint string_key_len;
        ulong num_key;
        int count = 0;
        int argc = ZEND_NUM_ARGS();

        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ZZZ|Z", &search, &replace, &subject, &zcount) == SUCCESS)
        {
            if (Z_REFCOUNT_PP(subject) > 1)
            {
                origin_subject = *subject;
            }
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored)
    {
        openrasp_str_replace_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, TAINT, 1, origin_subject);
    }
}

OPENRASP_HOOK_FUNCTION(str_ireplace, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT TSRMLS_CC);
    zval *origin_subject = nullptr;
    if (!type_ignored)
    {
        zval **subject, **search, **replace, **subject_entry, **zcount = NULL;
        char *string_key;
        uint string_key_len;
        ulong num_key;
        int count = 0;
        int argc = ZEND_NUM_ARGS();

        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ZZZ|Z", &search, &replace, &subject, &zcount) == SUCCESS)
        {
            if (Z_REFCOUNT_PP(subject) > 1)
            {
                origin_subject = *subject;
            }
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored)
    {
        openrasp_str_replace_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, TAINT, 0, origin_subject);
    }
}

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
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
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
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
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

typedef struct ReplaceItem_t
{
    int pos;
    size_t erase_length;
    NodeSequence insert_ns;
} ReplaceItem;

static void taint_formatted_print(NodeSequence &ns, int ht, int use_array, int format_offset TSRMLS_DC)
{
    zval ***args, **z_format;
    int argc, inpos = 0, temppos;
    int alignment, currarg, adjusting, argnum, width, precision;
    char *format, padding;
    int always_sign;
    int format_len;
    std::vector<ReplaceItem> replace_tiems;

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
        ns = openrasp_taint_sequence(*args[format_offset]);
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
            inpos += 2;
            replace_tiems.push_back({inpos, 1, 0});
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
            if (openrasp_taint_possible(*(args[argnum])))
            {
                item_ns = openrasp_taint_sequence(*(args[argnum]));
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
                zval *origin_args_argnum = *(args[argnum]);
                SEPARATE_ZVAL(args[argnum]);
                openrasp_taint_deep_copy(origin_args_argnum, *(args[argnum])TSRMLS_CC);
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
                replace_tiems.push_back({percentage_mark_pos, inpos - percentage_mark_pos + 1, item_ns});
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
                    replace_tiems.push_back({percentage_mark_pos, inpos - percentage_mark_pos + 1, Z_STRLEN(retval)});
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
    auto item = replace_tiems.rbegin();
    while (item != replace_tiems.rend())
    {
        ns.erase(item->pos, item->erase_length);
        ns.insert(item->pos, item->insert_ns);
        ++item;
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
    str_unchanege_taint(*arg, return_value TSRMLS_CC);
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
            openrasp_taint_possible(zstr))
        {
            NodeSequence ns = openrasp_taint_sequence(zstr);
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
                    if (idx < size - 1)
                    {
                        found = str.find(delim, start);
                        if (found != std::string::npos)
                        {
                            openrasp_taint_mark(*ele_value, new NodeSequence(ns.sub(start, found - start)) TSRMLS_CC);
                            start = found + delim.length();
                        }
                    }
                    else if (idx == size - 1)
                    {
                        if (limit > 0)
                        {
                            openrasp_taint_mark(*ele_value, new NodeSequence(ns.sub(start)) TSRMLS_CC);
                        }
                        else
                        {
                            found = str.find(delim, start);
                            if (found != std::string::npos)
                            {
                                openrasp_taint_mark(*ele_value, new NodeSequence(ns.sub(start, found - start)) TSRMLS_CC);
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
    if (IS_STRING != Z_TYPE_P(return_value) || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }

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
                ns.append(openrasp_taint_sequence(*tmp));
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
                ns.append(openrasp_taint_sequence(&expr));
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
                ns.append(openrasp_taint_sequence(&tmp_val));
                zval_dtor(&tmp_val);
                break;
            }

            if (++i != numelems)
            {
                ns.append(openrasp_taint_sequence(delim));
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
        openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
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
    if (IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && openrasp_taint_possible(zstr))
    {
        char *c = Z_STRVAL_P(zstr);
        int len = Z_STRLEN_P(zstr);
        NodeSequence ns = openrasp_taint_sequence(zstr);
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
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
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

void post_global_strtolower_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *arg;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE)
    {
        return;
    }
    str_unchanege_taint(arg, return_value TSRMLS_CC);
}

void post_global_strtoupper_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *arg;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE)
    {
        return;
    }
    str_unchanege_taint(arg, return_value TSRMLS_CC);
}

static void openrasp_str_replace_in_subject(zval *search, zval *replace, zval **subject, zval *result, int case_sensitivity, int *replace_count TSRMLS_DC)
{
    zval **search_entry = nullptr;
    zval **replace_entry = nullptr;

    /* Make sure we're dealing with strings. */
    convert_to_string_ex(subject);
    NodeSequence ns_subject = openrasp_taint_sequence(*subject);
    std::string str_subject(Z_STRVAL_PP(subject), Z_STRLEN_PP(subject));
    if (Z_STRLEN_PP(subject) == 0)
    {
        return;
    }
    NodeSequence ns_replace;
    std::string str_replace;

    /* If search is an array */
    if (Z_TYPE_P(search) == IS_ARRAY)
    {
        zend_hash_internal_pointer_reset(Z_ARRVAL_P(search));

        if (Z_TYPE_P(replace) == IS_ARRAY)
        {
            zend_hash_internal_pointer_reset(Z_ARRVAL_P(replace));
        }
        else
        {
            /* Set replacement value to the passed one */
            ns_replace = openrasp_taint_sequence(replace);
            str_replace = std::string(Z_STRVAL_P(replace), Z_STRLEN_P(replace));
        }

        /* For each entry in the search array, get the entry */
        while (zend_hash_get_current_data(Z_ARRVAL_P(search), (void **)&search_entry) == SUCCESS)
        {
            std::string str_search_entry = std::string(Z_STRVAL_PP(search_entry), Z_STRLEN_PP(search_entry));
            NodeSequence ns_search_entry = openrasp_taint_sequence(*search_entry);
            /* Make sure we're dealing with strings. */
            SEPARATE_ZVAL(search_entry);
            convert_to_string(*search_entry);
            if (Z_STRLEN_PP(search_entry) == 0)
            {
                zend_hash_move_forward(Z_ARRVAL_P(search));
                if (Z_TYPE_P(replace) == IS_ARRAY)
                {
                    zend_hash_move_forward(Z_ARRVAL_P(replace));
                }
                continue;
            }

            /* If replace is an array. */
            if (Z_TYPE_P(replace) == IS_ARRAY)
            {
                /* Get current entry */
                if (zend_hash_get_current_data(Z_ARRVAL_P(replace), (void **)&replace_entry) == SUCCESS)
                {
                    /* Make sure we're dealing with strings. */
                    convert_to_string_ex(replace_entry);
                    ns_replace = openrasp_taint_sequence(*replace_entry);
                    str_replace = std::string(Z_STRVAL_PP(replace_entry), Z_STRLEN_PP(replace_entry));
                    zend_hash_move_forward(Z_ARRVAL_P(replace));
                }
                else
                {
                    ns_replace = NodeSequence(0);
                    str_replace = "";
                }
            }
            size_t found = 0;
            do
            {
                if (!case_sensitivity)
                {
                    found = openrasp::find_case_insensitive(str_subject, str_search_entry, found);
                }
                else
                {
                    found = str_subject.find(str_search_entry, found);
                }
                if (found != std::string::npos)
                {
                    str_subject.erase(found, str_search_entry.length());
                    ns_subject.erase(found, str_search_entry.length());
                    str_subject.insert(found, str_replace);
                    ns_subject.insert(found, ns_replace);
                    if (nullptr != replace_count)
                    {
                        (*replace_count)++;
                    }
                }
            } while (found != std::string::npos);

            if (ns_subject.taintedSize() && Z_TYPE_P(result) == IS_STRING && Z_STRLEN_P(result) &&
                ns_subject.length() == Z_STRLEN_P(result))
            {
                openrasp_taint_mark(result, new NodeSequence(ns_subject) TSRMLS_CC);
            }
            zend_hash_move_forward(Z_ARRVAL_P(search));
        }
    }
    else
    {
        std::string str_search = std::string(Z_STRVAL_P(search), Z_STRLEN_P(search));
        NodeSequence ns_search = openrasp_taint_sequence(search);
        ns_replace = openrasp_taint_sequence(replace);
        str_replace = std::string(Z_STRVAL_P(replace), Z_STRLEN_P(replace));
        size_t found = 0;
        do
        {
            if (!case_sensitivity)
            {
                found = openrasp::find_case_insensitive(str_subject, str_search, found);
            }
            else
            {
                found = str_subject.find(str_search, found);
            }
            if (found != std::string::npos)
            {
                str_subject.erase(found, str_search.length());
                ns_subject.erase(found, str_search.length());
                str_subject.insert(found, str_replace);
                ns_subject.insert(found, ns_replace);
                if (nullptr != replace_count)
                {
                    (*replace_count)++;
                }
            }
        } while (found != std::string::npos);
        if (ns_subject.taintedSize() && Z_TYPE_P(result) == IS_STRING && Z_STRLEN_P(result) &&
            ns_subject.length() == Z_STRLEN_P(result))
        {
            openrasp_taint_mark(result, new NodeSequence(ns_subject) TSRMLS_CC);
        }
    }
}

static void openrasp_str_replace_common(OPENRASP_INTERNAL_FUNCTION_PARAMETERS, int case_sensitivity, zval *origin_subject)
{
    zval **subject, **search, **replace, **subject_entry, **zcount = NULL;
    char *string_key;
    uint string_key_len;
    ulong num_key;
    int count = 0;
    int argc = ZEND_NUM_ARGS();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ZZZ|Z", &search, &replace, &subject, &zcount) == FAILURE)
    {
        return;
    }

    SEPARATE_ZVAL(search);
    SEPARATE_ZVAL(replace);
    SEPARATE_ZVAL(subject);
    if (origin_subject != nullptr)
    {
        openrasp_taint_deep_copy(origin_subject, *subject TSRMLS_CC);
    }

    /* Make sure we're dealing with strings and do the replacement. */
    if (Z_TYPE_PP(search) != IS_ARRAY)
    {
        convert_to_string_ex(search);
        convert_to_string_ex(replace);
    }
    else if (Z_TYPE_PP(replace) != IS_ARRAY)
    {
        convert_to_string_ex(replace);
    }

    /* if subject is an array */
    if (Z_TYPE_PP(subject) == IS_ARRAY)
    {
        zend_hash_internal_pointer_reset(Z_ARRVAL_PP(subject));
        while (zend_hash_get_current_data(Z_ARRVAL_PP(subject), (void **)&subject_entry) == SUCCESS)
        {
            zval **ele_value;
            switch (zend_hash_get_current_key_ex(Z_ARRVAL_PP(subject), &string_key,
                                                 &string_key_len, &num_key, 0, NULL))
            {
            case HASH_KEY_IS_STRING:
                if (zend_hash_find(Z_ARRVAL_P(return_value), string_key, string_key_len + 1, (void **)&ele_value) != SUCCESS ||
                    Z_TYPE_PP(subject_entry) != Z_TYPE_PP(ele_value))
                {
                    continue;
                }
                break;
            case HASH_KEY_IS_LONG:
                if (zend_hash_index_find(Z_ARRVAL_P(return_value), num_key, (void **)&ele_value) != SUCCESS ||
                    Z_TYPE_PP(subject_entry) != Z_TYPE_PP(ele_value))
                {
                    continue;
                }
                break;
            }

            if (Z_TYPE_PP(subject_entry) != IS_ARRAY && Z_TYPE_PP(subject_entry) != IS_OBJECT)
            {
                SEPARATE_ZVAL(subject_entry);
                openrasp_str_replace_in_subject(*search, *replace, subject_entry, *ele_value, case_sensitivity, ((argc > 3) ? &count : NULL) TSRMLS_CC);
            }
            else
            {
                openrasp_taint_deep_copy(*subject_entry, *ele_value TSRMLS_CC);
            }
            zend_hash_move_forward(Z_ARRVAL_PP(subject));
        }
    }
    else
    { /* if subject is not an array */
        openrasp_str_replace_in_subject(*search, *replace, subject, return_value, case_sensitivity, ((argc > 3) ? &count : NULL) TSRMLS_CC);
    }
}

void post_global_str_pad_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    /* Input arguments */
    zval *z_input = nullptr;
    long pad_length; /* Length to pad to */

    /* Helper variables */
    size_t num_pad_chars; /* Number of padding characters (total - input size) */
    char *result = NULL;  /* Resulting string */
    int result_len = 0;   /* Length of the resulting string */
    zval *z_pad_str = nullptr;
    long pad_type_val = STR_PAD_RIGHT; /* The padding type value */
    int i, left_pad = 0, right_pad = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl|zl", &z_input, &pad_length, &z_pad_str, &pad_type_val) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(z_input) != IS_STRING)
    {
        return;
    }

    NodeSequence ns_pad;
    if (nullptr == z_pad_str)
    {
        ns_pad = NodeSequence(1);
    }
    else
    {
        if (Z_TYPE_P(z_pad_str) != IS_STRING)
        {
            return;
        }
        else
        {
            if (Z_STRLEN_P(z_pad_str) == 0)
            {
                return;
            }
            ns_pad = openrasp_taint_sequence(z_pad_str);
        }
    }

    if (pad_length <= 0 || (pad_length - Z_STRLEN_P(z_input)) <= 0)
    {
        str_unchanege_taint(z_input, return_value TSRMLS_CC);
        return;
    }

    if (pad_type_val < STR_PAD_LEFT || pad_type_val > STR_PAD_BOTH)
    {
        return;
    }

    num_pad_chars = pad_length - Z_STRLEN_P(z_input);
    if (num_pad_chars >= INT_MAX)
    {
        return;
    }

    NodeSequence ns = openrasp_taint_sequence(z_input);
    switch (pad_type_val)
    {
    case STR_PAD_RIGHT:
        left_pad = 0;
        right_pad = num_pad_chars;
        break;

    case STR_PAD_LEFT:
        left_pad = num_pad_chars;
        right_pad = 0;
        break;

    case STR_PAD_BOTH:
        left_pad = num_pad_chars / 2;
        right_pad = num_pad_chars - left_pad;
        break;
    }

    NodeSequence ns_left;
    while (ns_left.length() < left_pad)
    {
        ns_left.append(ns_pad);
    }
    ns_left.erase(left_pad);
    ns.insert(0, ns_left);

    NodeSequence ns_right;
    while (ns_right.length() < right_pad)
    {
        ns_right.append(ns_pad);
    }
    ns_right.erase(right_pad);
    ns.append(ns_right);

    if (ns.taintedSize() &&
        Z_TYPE_P(return_value) == IS_STRING &&
        Z_STRLEN_P(return_value) &&
        ns.length() == Z_STRLEN_P(return_value))
    {
        openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
    }
}

static int openrasp_needle_char(zval *needle, char *target TSRMLS_DC)
{
    switch (Z_TYPE_P(needle))
    {
    case IS_LONG:
    case IS_BOOL:
        *target = (char)Z_LVAL_P(needle);
        return SUCCESS;
    case IS_NULL:
        *target = '\0';
        return SUCCESS;
    case IS_DOUBLE:
        *target = (char)(int)Z_DVAL_P(needle);
        return SUCCESS;
    case IS_OBJECT:
    {
        zval holder = *needle;
        zval_copy_ctor(&(holder));
        convert_to_long(&(holder));
        if (Z_TYPE(holder) != IS_LONG)
        {
            return FAILURE;
        }
        *target = (char)Z_LVAL(holder);
        return SUCCESS;
    }
    default:
    {
        return FAILURE;
    }
    }
}

void post_global_strstr_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }

    zval *needle;
    zval *z_haystack;
    const char *found = nullptr;
    char needle_char[2];
    long found_offset;
    zend_bool part = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|b", &z_haystack, &needle, &part) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(z_haystack))
    {
        NodeSequence ns = openrasp_taint_sequence(z_haystack);
        char *haystack = Z_STRVAL_P(z_haystack);
        int haystack_len = Z_STRLEN_P(z_haystack);
        if (Z_TYPE_P(needle) == IS_STRING)
        {
            if (!Z_STRLEN_P(needle))
            {
                return;
            }

            found = php_memnstr(haystack, Z_STRVAL_P(needle), Z_STRLEN_P(needle), haystack + haystack_len);
        }
        else
        {
            if (openrasp_needle_char(needle, needle_char TSRMLS_CC) != SUCCESS)
            {
                return;
            }
            needle_char[1] = 0;

            found = php_memnstr(haystack, needle_char, 1, haystack + haystack_len);
        }
        if (found)
        {
            found_offset = found - haystack;
            if (part)
            {
                ns.erase(found_offset);
            }
            else
            {
                ns.erase(0, found_offset);
            }
        }
        if (ns.taintedSize() &&
            ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
        }
    }
}

void post_global_substr_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }

    zval *z_str = nullptr;
    long l = 0, f;
    int argc = ZEND_NUM_ARGS();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl|l", &z_str, &f, &l) == FAILURE)
    {
        return;
    }
    if (openrasp_taint_possible(z_str))
    {
        int str_len = Z_STRLEN_P(z_str);
        NodeSequence ns = openrasp_taint_sequence(z_str);
        if (argc > 2)
        {
            if ((l < 0 && -l > str_len))
            {
                return;
            }
            else if (l > str_len)
            {
                l = str_len;
            }
        }
        else
        {
            l = str_len;
        }

        if (f > str_len)
        {
            return;
        }
        else if (f < 0 && -f > str_len)
        {
            f = 0;
        }

        if (l < 0 && (l + str_len - f) < 0)
        {
            return;
        }

        /* if "from" position is negative, count start position from the end
	 * of the string
	 */
        if (f < 0)
        {
            f = str_len + f;
            if (f < 0)
            {
                f = 0;
            }
        }

        /* if "length" position is negative, set it to the length
	 * needed to stop that many chars from the end of the string
	 */
        if (l < 0)
        {
            l = (str_len - f) + l;
            if (l < 0)
            {
                l = 0;
            }
        }

        if (f >= str_len)
        {
            return;
        }

        if ((f + l) > str_len)
        {
            l = str_len - f;
        }

        NodeSequence ns_sub = ns.sub(f, l);
        if (ns_sub.taintedSize() &&
            ns_sub.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns_sub) TSRMLS_CC);
        }
    }
}

void post_global_stristr_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }

    zval *needle;
    zval *z_haystack;
    const char *found = nullptr;
    char needle_char[2];
    long found_offset;
    zend_bool part = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|b", &z_haystack, &needle, &part) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(z_haystack))
    {
        NodeSequence ns = openrasp_taint_sequence(z_haystack);
        char *haystack = Z_STRVAL_P(z_haystack);
        int haystack_len = Z_STRLEN_P(z_haystack);
        char *haystack_dup = estrndup(haystack, haystack_len);
        if (Z_TYPE_P(needle) == IS_STRING)
        {
            char *orig_needle;
            if (!Z_STRLEN_P(needle))
            {
                efree(haystack_dup);
                return;
            }
            orig_needle = estrndup(Z_STRVAL_P(needle), Z_STRLEN_P(needle));
            found = php_stristr(haystack_dup, orig_needle, haystack_len, Z_STRLEN_P(needle));
            efree(orig_needle);
        }
        else
        {
            if (openrasp_needle_char(needle, needle_char TSRMLS_CC) != SUCCESS)
            {
                efree(haystack_dup);
                return;
            }
            needle_char[1] = 0;

            found = php_stristr(haystack_dup, needle_char, haystack_len, 1);
        }
        if (found)
        {
            found_offset = found - haystack_dup;
            if (part)
            {
                ns.erase(found_offset);
            }
            else
            {
                ns.erase(0, found_offset);
            }
        }
        if (ns.taintedSize() &&
            ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
        }
        efree(haystack_dup);
    }
}

void post_global_dirname_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0 ||
        (Z_STRLEN_P(return_value) == 1 && (strcmp(Z_STRVAL_P(return_value), "/") == 0 || strcmp(Z_STRVAL_P(return_value), ".") == 0)))
    {
        return;
    }

    zval *z_str;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z_str) == FAILURE)
    {
        return;
    }
    if (openrasp_taint_possible(z_str))
    {
        NodeSequence ns = openrasp_taint_sequence(z_str);
        ns.erase(Z_STRLEN_P(return_value));
        if (ns.taintedSize() &&
            ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns) TSRMLS_CC);
        }
    }
}

void post_global_basename_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }

    zval *z_string = nullptr;
    zval *z_suffix = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|z", &z_string, &z_suffix) == FAILURE)
    {
        return;
    }
    if (openrasp_taint_possible(z_string))
    {
        NodeSequence ns = openrasp_taint_sequence(z_string);
        int string_len = Z_STRLEN_P(z_string);
        int suffix_len = (nullptr != z_suffix && Z_TYPE_P(z_suffix) == IS_STRING) ? Z_STRLEN_P(z_suffix) : 0;
        NodeSequence ns_base = ns.sub(string_len - (Z_STRLEN_P(return_value) + suffix_len), Z_STRLEN_P(return_value));
        if (ns_base.taintedSize() &&
            ns_base.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns_base) TSRMLS_CC);
        }
    }
}