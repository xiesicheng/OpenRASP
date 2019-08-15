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

static void trim_taint(zend_string *str, char *what, size_t what_len, int mode, zval *return_value);
static int openrasp_needle_char(zval *needle, char *target);
static void openrasp_str_replace_common(INTERNAL_FUNCTION_PARAMETERS, int case_sensitivity);
static void taint_formatted_print(zend_execute_data *execute_data, int use_array, int format_offset, NodeSequence &ns);

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
POST_HOOK_FUNCTION(str_replace, TAINT);
POST_HOOK_FUNCTION(str_ireplace, TAINT);

#ifdef sprintf
#undef sprintf
#endif
OPENRASP_HOOK_FUNCTION(sprintf, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT);
    static bool processing = false;
    NodeSequence ns;
    if (!type_ignored)
    {
        if (!processing)
        {
            processing = true;
            taint_formatted_print(execute_data, 0, 0, ns);
            processing = false;
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored && processing == false)
    {
        if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns));
        }
    }
}
#ifndef sprintf
#define sprintf php_sprintf
#endif

OPENRASP_HOOK_FUNCTION(vsprintf, taint)
{
    bool type_ignored = openrasp_check_type_ignored(TAINT);
    static bool processing = false;
    NodeSequence ns;
    if (!type_ignored)
    {
        if (!processing)
        {
            processing = true;
            taint_formatted_print(execute_data, 1, 0, ns);
            processing = false;
        }
    }
    origin_function(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (!type_ignored && processing == false)
    {
        if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns));
        }
    }
}

void post_global_strval_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **arg;

    if (ZEND_NUM_ARGS() != 1 || zend_get_parameters_ex(1, &arg) == FAILURE)
    {
        WRONG_PARAM_COUNT;
    }
    str_unchanege_taint(*arg, return_value);
}

void post_global_explode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    int size = 0;
    if (Z_TYPE_P(return_value) == IS_ARRAY && (size = zend_hash_num_elements(Z_ARRVAL_P(return_value))) > 0)
    {
        zval *zdelim = nullptr;
        zval *zstr = nullptr;
        long limit = ZEND_LONG_MAX; /* No limit */

        if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz|l", &zdelim, &zstr, &limit) == FAILURE)
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

            zval *val;
            zend_string *key;
            zend_ulong idx;
            ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(return_value), idx, key, val)
            {
                if (Z_TYPE_P(val) == IS_STRING && nullptr == key)
                {
                    if (idx < size - 1)
                    {
                        found = str.find(delim, start);
                        if (found != std::string::npos)
                        {
                            openrasp_taint_mark(val, new NodeSequence(ns.sub(start, found - start)));
                            start = found + delim.length();
                        }
                    }
                    else if (idx == size - 1)
                    {
                        if (limit > 0)
                        {
                            openrasp_taint_mark(val, new NodeSequence(ns.sub(start)));
                        }
                        else
                        {
                            found = str.find(delim, start);
                            if (found != std::string::npos)
                            {
                                openrasp_taint_mark(val, new NodeSequence(ns.sub(start, found - start)));
                            }
                        }
                    }
                }
            }
            ZEND_HASH_FOREACH_END();
        }
    }
}

void post_global_implode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (IS_STRING != Z_TYPE_P(return_value) || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zval *arg1 = nullptr;
    zval *arg2 = nullptr;
    zval *arr = nullptr;
    zend_string *delim = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|z", &arg1, &arg2) == FAILURE)
    {
        return;
    }
    if (arg2 == nullptr)
    {
        if (Z_TYPE_P(arg1) != IS_ARRAY)
        {
            return;
        }
        delim = ZSTR_EMPTY_ALLOC();
        arr = arg1;
    }
    else
    {
        if (Z_TYPE_P(arg1) == IS_ARRAY)
        {
            delim = zval_get_string(arg2);
            arr = arg1;
        }
        else if (Z_TYPE_P(arg2) == IS_ARRAY)
        {
            delim = zval_get_string(arg1);
            arr = arg2;
        }
        else
        {
            return;
        }
    }

    NodeSequence ns;
    {
        zval *tmp;
        int numelems;

        numelems = zend_hash_num_elements(Z_ARRVAL_P(arr));

        if (numelems == 0)
        {
            return;
        }
        else if (numelems == 1)
        {
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), tmp)
            {
                if (IS_STRING == Z_TYPE_P(tmp))
                {
                    ns.append(openrasp_taint_sequence(tmp));
                }
                return;
            }
            ZEND_HASH_FOREACH_END();
        }

        int i = 0;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), tmp)
        {
            if (Z_TYPE_P(tmp) == IS_LONG)
            {
                zend_long val = Z_LVAL_P(tmp);

                if (val <= 0)
                {
                    ns.append(1);
                }
                while (val)
                {
                    val /= 10;
                    ns.append(1);
                }
            }
            else
            {
                zend_string *strptr = zval_get_string(tmp);
                ns.append(openrasp_taint_sequence(strptr));
                zend_string_release(strptr);
            }

            if (++i != numelems)
            {
                ns.append(openrasp_taint_sequence(delim));
            }
        }
        ZEND_HASH_FOREACH_END();
    }
    zend_string_release(delim);
    if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
    {
        openrasp_taint_mark(return_value, new NodeSequence(ns));
    }
}

void post_global_join_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    return post_global_implode_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static inline int php_charmask(unsigned char *input, size_t len, char *mask)
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
                php_error_docref(nullptr, E_WARNING, "Invalid '..'-range, no character to the left of '..'");
                result = FAILURE;
                continue;
            }
            if (input + 2 >= end)
            { /* there is no 'right' char */
                php_error_docref(nullptr, E_WARNING, "Invalid '..'-range, no character to the right of '..'");
                result = FAILURE;
                continue;
            }
            if (input[-1] > input[2])
            { /* wrong order */
                php_error_docref(nullptr, E_WARNING, "Invalid '..'-range, '..'-range needs to be incrementing");
                result = FAILURE;
                continue;
            }
            /* FIXME: better error (a..b..c is the only left possibility?) */
            php_error_docref(nullptr, E_WARNING, "Invalid '..'-range");
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

void trim_taint(zend_string *str, char *what, size_t what_len, int mode, zval *return_value)
{
    if (openrasp_taint_possible(str))
    {
        const char *c = ZSTR_VAL(str);
        size_t len = ZSTR_LEN(str);
        NodeSequence ns = openrasp_taint_sequence(str);
        register size_t i;
        char mask[256];

        if (what)
        {
            if (what_len == 1)
            {
                char p = *what;
                if (mode & 1)
                {
                    for (i = 0; i < len; i++)
                    {
                        if (c[i] == p)
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
                    if (len > 0)
                    {
                        i = len - 1;
                        do
                        {
                            if (c[i] == p)
                            {
                                ns.erase(ns.length() - 1);
                            }
                            else
                            {
                                break;
                            }
                        } while (i-- != 0);
                    }
                }
            }
            else
            {
                php_charmask((unsigned char *)what, what_len, mask);

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
                    if (len > 0)
                    {
                        i = len - 1;
                        do
                        {
                            if (mask[(unsigned char)c[i]])
                            {
                                ns.erase(ns.length() - 1);
                            }
                            else
                            {
                                break;
                            }
                        } while (i-- != 0);
                    }
                }
            }
        }
        else
        {
            if (mode & 1)
            {
                for (i = 0; i < len; i++)
                {
                    if ((unsigned char)c[i] <= ' ' &&
                        (c[i] == ' ' || c[i] == '\n' || c[i] == '\r' || c[i] == '\t' || c[i] == '\v' || c[i] == '\0'))
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
                if (len > 0)
                {
                    i = len - 1;
                    do
                    {
                        if ((unsigned char)c[i] <= ' ' &&
                            (c[i] == ' ' || c[i] == '\n' || c[i] == '\r' || c[i] == '\t' || c[i] == '\v' || c[i] == '\0'))
                        {
                            ns.erase(ns.length() - 1);
                        }
                        else
                        {
                            break;
                        }
                    } while (i-- != 0);
                }
            }
        }
        if (ns.taintedSize() && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value) && ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns));
        }
    }
}

void post_global_trim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (IS_STRING != Z_TYPE_P(return_value) || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zend_string *str = nullptr;
    zend_string *what = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|S", &str, &what) == FAILURE)
    {
        return;
    }
    trim_taint(str, (what ? ZSTR_VAL(what) : nullptr), (what ? ZSTR_LEN(what) : 0), 3, return_value);
}

void post_global_ltrim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (IS_STRING != Z_TYPE_P(return_value) || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zend_string *str = nullptr;
    zend_string *what = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|S", &str, &what) == FAILURE)
    {
        return;
    }
    trim_taint(str, (what ? ZSTR_VAL(what) : nullptr), (what ? ZSTR_LEN(what) : 0), 1, return_value);
}

void post_global_rtrim_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (IS_STRING != Z_TYPE_P(return_value) || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zend_string *str = nullptr;
    zend_string *what = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|S", &str, &what) == FAILURE)
    {
        return;
    }
    trim_taint(str, (what ? ZSTR_VAL(what) : nullptr), (what ? ZSTR_LEN(what) : 0), 2, return_value);
}

void post_global_strtolower_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *str = nullptr;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &str) == FAILURE)
    {
        return;
    }
    str_unchanege_taint(str, return_value);
}

void post_global_strtoupper_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *str = nullptr;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &str) == FAILURE)
    {
        return;
    }
    str_unchanege_taint(str, return_value);
}

void post_global_str_pad_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zend_string *input;   /* Input string */
    zend_long pad_length; /* Length to pad to */

    /* Helper variables */
    size_t num_pad_chars; /* Number of padding characters (total - input size) */
    zend_string *zs_pad_str = nullptr;
    zend_long pad_type_val = STR_PAD_RIGHT; /* The padding type value */
    size_t i, left_pad = 0, right_pad = 0;
    zend_string *result = nullptr; /* Resulting string */

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sl|Sl", &input, &pad_length, &zs_pad_str, &pad_type_val) == FAILURE)
    {
        return;
    }

    NodeSequence ns_pad;
    if (nullptr == zs_pad_str)
    {
        ns_pad = NodeSequence(1);
    }
    else
    {
        if (ZSTR_LEN(zs_pad_str) == 0)
        {
            return;
        }
        ns_pad = openrasp_taint_sequence(zs_pad_str);
    }

    if (pad_length < 0 || (size_t)pad_length <= ZSTR_LEN(input))
    {
        str_unchanege_taint(input, return_value);
    }

    if (pad_type_val < STR_PAD_LEFT || pad_type_val > STR_PAD_BOTH)
    {
        return;
    }

    num_pad_chars = pad_length - ZSTR_LEN(input);
    if (num_pad_chars >= INT_MAX)
    {
        return;
    }

    NodeSequence ns = openrasp_taint_sequence(input);
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
        openrasp_taint_mark(return_value, new NodeSequence(ns));
    }
}

int openrasp_needle_char(zval *needle, char *target)
{
    switch (Z_TYPE_P(needle))
    {
    case IS_LONG:
        *target = (char)Z_LVAL_P(needle);
        return SUCCESS;
    case IS_NULL:
    case IS_FALSE:
        *target = '\0';
        return SUCCESS;
    case IS_TRUE:
        *target = '\1';
        return SUCCESS;
    case IS_DOUBLE:
        *target = (char)(int)Z_DVAL_P(needle);
        return SUCCESS;
    case IS_OBJECT:
        *target = (char)zval_get_long(needle);
        return SUCCESS;
    default:
        php_error_docref(nullptr, E_WARNING, "needle is not a string or an integer");
        return FAILURE;
    }
}

void post_global_strstr_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zval *needle;
    zend_string *haystack;
    char *found = nullptr;
    char needle_char[2];
    zend_long found_offset;
    zend_bool part = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sz|b", &haystack, &needle, &part) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(haystack))
    {
        NodeSequence ns = openrasp_taint_sequence(haystack);
        if (Z_TYPE_P(needle) == IS_STRING)
        {
            if (!Z_STRLEN_P(needle))
            {
                return;
            }

            found = (char *)php_memnstr(ZSTR_VAL(haystack), Z_STRVAL_P(needle), Z_STRLEN_P(needle), ZSTR_VAL(haystack) + ZSTR_LEN(haystack));
        }
        else
        {
            if (openrasp_needle_char(needle, needle_char) != SUCCESS)
            {
                return;
            }
            needle_char[1] = 0;

            found = (char *)php_memnstr(ZSTR_VAL(haystack), needle_char, 1, ZSTR_VAL(haystack) + ZSTR_LEN(haystack));
        }
        if (found)
        {
            found_offset = found - ZSTR_VAL(haystack);
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
            openrasp_taint_mark(return_value, new NodeSequence(ns));
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
    zend_string *haystack;
    char *found = nullptr;
    size_t found_offset;
    char *haystack_dup;
    char needle_char[2];
    zend_bool part = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sz|b", &haystack, &needle, &part) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(haystack))
    {
        NodeSequence ns = openrasp_taint_sequence(haystack);
        haystack_dup = estrndup(ZSTR_VAL(haystack), ZSTR_LEN(haystack));

        if (Z_TYPE_P(needle) == IS_STRING)
        {
            char *orig_needle;
            if (!Z_STRLEN_P(needle))
            {
                efree(haystack_dup);
                return;
            }
            orig_needle = estrndup(Z_STRVAL_P(needle), Z_STRLEN_P(needle));
            found = php_stristr(haystack_dup, orig_needle, ZSTR_LEN(haystack), Z_STRLEN_P(needle));
            efree(orig_needle);
        }
        else
        {
            if (openrasp_needle_char(needle, needle_char) != SUCCESS)
            {
                efree(haystack_dup);
                return;
            }
            needle_char[1] = 0;

            found = php_stristr(haystack_dup, needle_char, ZSTR_LEN(haystack), 1);
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
            openrasp_taint_mark(return_value, new NodeSequence(ns));
        }
        efree(haystack_dup);
    }
}

void post_global_substr_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0)
    {
        return;
    }
    zend_string *str;
    zend_long l = 0, f;
    int argc = ZEND_NUM_ARGS();

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sl|l", &str, &f, &l) == FAILURE)
    {
        return;
    }
    if (openrasp_taint_possible(str))
    {
        NodeSequence ns = openrasp_taint_sequence(str);
        if (argc > 2)
        {
            if ((l < 0 && (size_t)(-l) > ZSTR_LEN(str)))
            {
                return;
            }
            else if (l > (zend_long)ZSTR_LEN(str))
            {
                l = ZSTR_LEN(str);
            }
        }
        else
        {
            l = ZSTR_LEN(str);
        }

        if (f > (zend_long)ZSTR_LEN(str))
        {
            return;
        }
        else if (f < 0 && -f > ZSTR_LEN(str))
        {
            f = 0;
        }

        if (l < 0 && (l + (zend_long)ZSTR_LEN(str) - f) < 0)
        {
            return;
        }

        /* if "from" position is negative, count start position from the end
	 * of the string
	 */
        if (f < 0)
        {
            f = (zend_long)ZSTR_LEN(str) + f;
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
            l = ((zend_long)ZSTR_LEN(str) - f) + l;
            if (l < 0)
            {
                l = 0;
            }
        }

        if (f > (zend_long)ZSTR_LEN(str))
        {
            return;
        }

        if ((size_t)l > ZSTR_LEN(str) - (size_t)f)
        {
            l = ZSTR_LEN(str) - f;
        }
        NodeSequence ns_sub = ns.sub(f, l);
        if (ns_sub.taintedSize() &&
            ns_sub.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns_sub));
        }
    }
}

void post_global_dirname_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    if (Z_TYPE_P(return_value) != IS_STRING || Z_STRLEN_P(return_value) == 0 ||
        (Z_STRLEN_P(return_value) == 1 && (strcmp(Z_STRVAL_P(return_value), "/") == 0 || strcmp(Z_STRVAL_P(return_value), ".") == 0)))
    {
        return;
    }

    zend_string *str;
    zend_long levels = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|l", &str, &levels) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(str))
    {
        NodeSequence ns = openrasp_taint_sequence(str);
        ns.erase(Z_STRLEN_P(return_value));
        if (ns.taintedSize() &&
            ns.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns));
        }
    }
}

void post_global_basename_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    char *suffix = nullptr;
    size_t suffix_len = 0;
    zend_string *string;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|s", &string, &suffix, &suffix_len) == FAILURE)
    {
        return;
    }

    if (openrasp_taint_possible(string))
    {
        NodeSequence ns = openrasp_taint_sequence(string);
        NodeSequence ns_base = ns.sub(ZSTR_LEN(string) - (Z_STRLEN_P(return_value) + suffix_len), Z_STRLEN_P(return_value));
        if (ns_base.taintedSize() &&
            ns_base.length() == Z_STRLEN_P(return_value))
        {
            openrasp_taint_mark(return_value, new NodeSequence(ns_base));
        }
    }
}

static void openrasp_str_replace_in_subject(zval *search, zval *replace, zval *subject, zval *result, int case_sensitivity)
{
    zval *search_entry = nullptr;
    zval *replace_entry = nullptr;
    zend_string *tmp_result = nullptr;
    zend_string *replace_entry_str = nullptr;
    zend_long replace_count = 0;
    zend_string *subject_str;
    uint32_t replace_idx;

    /* Make sure we're dealing with strings. */
    subject_str = zval_get_string(subject);
    NodeSequence ns_subject = openrasp_taint_sequence(subject);
    std::string str_subject(Z_STRVAL_P(subject), Z_STRLEN_P(subject));
    if (ZSTR_LEN(subject_str) == 0)
    {
        zend_string_release(subject_str);
        return;
    }
    NodeSequence ns_replace;
    std::string str_replace;

    /* If search is an array */
    if (Z_TYPE_P(search) == IS_ARRAY)
    {
        /* Duplicate subject string for repeated replacement */
        if (Z_TYPE_P(replace) == IS_ARRAY)
        {
            replace_idx = 0;
        }
        else
        {
            /* Set replacement value to the passed one */
            ns_replace = openrasp_taint_sequence(replace);
            str_replace = std::string(Z_STRVAL_P(replace), Z_STRLEN_P(replace));
        }

        /* For each entry in the search array, get the entry */
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(search), search_entry)
        {
            /* Make sure we're dealing with strings. */
            zend_string *search_str = zval_get_string(search_entry);
            NodeSequence ns_search_entry = openrasp_taint_sequence(search_str);
            std::string str_search_entry = std::string(ZSTR_VAL(search_str), ZSTR_LEN(search_str));
            if (ZSTR_LEN(search_str) == 0)
            {
                if (Z_TYPE_P(replace) == IS_ARRAY)
                {
                    replace_idx++;
                }
                zend_string_release(search_str);
                continue;
            }

            /* If replace is an array. */
            if (Z_TYPE_P(replace) == IS_ARRAY)
            {
                /* Get current entry */
                while (replace_idx < Z_ARRVAL_P(replace)->nNumUsed)
                {
                    replace_entry = &Z_ARRVAL_P(replace)->arData[replace_idx].val;
                    if (Z_TYPE_P(replace_entry) != IS_UNDEF)
                    {
                        break;
                    }
                    replace_idx++;
                }
                if (replace_idx < Z_ARRVAL_P(replace)->nNumUsed)
                {
                    /* Make sure we're dealing with strings. */
                    replace_entry_str = zval_get_string(replace_entry);

                    /* Set replacement value to the one we got from array */
                    ns_replace = openrasp_taint_sequence(replace_entry_str);
                    str_replace = std::string(ZSTR_VAL(replace_entry_str), ZSTR_LEN(replace_entry_str));

                    replace_idx++;
                }
                else
                {
                    /* We've run out of replacement strings, so use an empty one. */
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
                    replace_count++;
                }
            } while (found != std::string::npos);

            zend_string_release(search_str);

            if (replace_entry_str)
            {
                zend_string_release(replace_entry_str);
                replace_entry_str = nullptr;
            }
            if (ns_subject.taintedSize() && Z_TYPE_P(result) == IS_STRING && Z_STRLEN_P(result) &&
                ns_subject.length() == Z_STRLEN_P(result))
            {
                openrasp_taint_mark(result, new NodeSequence(ns_subject));
            }
        }
        ZEND_HASH_FOREACH_END();
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
                replace_count++;
            }
        } while (found != std::string::npos);
        if (ns_subject.taintedSize() && Z_TYPE_P(result) == IS_STRING && Z_STRLEN_P(result) &&
            ns_subject.length() == Z_STRLEN_P(result))
        {
            openrasp_taint_mark(result, new NodeSequence(ns_subject));
        }
    }
    zend_string_release(subject_str);
    return;
}

void openrasp_str_replace_common(INTERNAL_FUNCTION_PARAMETERS, int case_sensitivity)
{
    zval *subject, *search, *replace, *subject_entry, *zcount = nullptr;
    zval result;
    zend_string *string_key;
    zend_ulong num_key;
    zend_long count = 0;
    int argc = ZEND_NUM_ARGS();
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz|z", &search, &replace, &subject, &zcount) == FAILURE)
    {
        return;
    }
    /* Make sure we're dealing with strings and do the replacement. */
    if (Z_TYPE_P(search) != IS_ARRAY)
    {
        convert_to_string_ex(search);
        if (Z_TYPE_P(replace) != IS_STRING)
        {
            convert_to_string_ex(replace);
        }
    }
    else if (Z_TYPE_P(replace) != IS_ARRAY)
    {
        convert_to_string_ex(replace);
    }

    /* if subject is an array */
    if (Z_TYPE_P(subject) == IS_ARRAY)
    {
        /* For each subject entry, convert it to string, then perform replacement
		   and add the result to the return_value array. */
        ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(subject), num_key, string_key, subject_entry)
        {
            ZVAL_DEREF(subject_entry);
            zval *result_entry = nullptr;
            if (string_key != nullptr)
            {
                if ((result_entry = zend_hash_find(Z_ARRVAL_P(return_value), string_key)) == nullptr ||
                    Z_TYPE_P(result_entry) != Z_TYPE_P(subject_entry))
                {
                    continue;
                }
            }
            else
            {
                if ((result_entry = zend_hash_index_find(Z_ARRVAL_P(return_value), num_key)) == nullptr ||
                    Z_TYPE_P(result_entry) != Z_TYPE_P(subject_entry))
                {
                    continue;
                }
            }

            if (Z_TYPE_P(subject_entry) != IS_ARRAY && Z_TYPE_P(subject_entry) != IS_OBJECT)
            {
                openrasp_str_replace_in_subject(search, replace, subject_entry, result_entry, case_sensitivity);
            }
        }
        ZEND_HASH_FOREACH_END();
    }
    else
    { /* if subject is not an array */
        openrasp_str_replace_in_subject(search, replace, subject, return_value, case_sensitivity);
    }
}

void post_global_str_replace_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    openrasp_str_replace_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

void post_global_str_ireplace_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    openrasp_str_replace_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

typedef struct ReplaceItem_t
{
    int pos;
    size_t erase_length;
    NodeSequence insert_ns;
} ReplaceItem;

inline static int openrasp_sprintf_getnumber(char *buffer, size_t *pos)
{
    char *endptr;
    register zend_long num = ZEND_STRTOL(&buffer[*pos], &endptr, 10);
    register size_t i = 0;

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

void taint_formatted_print(zend_execute_data *execute_data, int use_array, int format_offset, NodeSequence &ns)
{
    zval *newargs = NULL;
    zval *args, *z_format;
    int argc;
    size_t size = 240, inpos = 0, temppos;
    int alignment, currarg, adjusting, argnum, width, precision;
    char *format, padding;
    int always_sign;
    size_t format_len;
    std::vector<ReplaceItem> replace_items;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "+", &args, &argc) == FAILURE)
    {
        return;
    }

    /* verify the number of args */
    if ((use_array && argc != (2 + format_offset)) ||
        (!use_array && argc < (1 + format_offset)))
    {
        return;
    }

    convert_to_string_ex(&args[format_offset]);
    if (use_array)
    {
        int i = 1;
        zval *zv;
        zval *array;

        z_format = &args[format_offset];
        array = &args[1 + format_offset];
        if (Z_TYPE_P(array) != IS_ARRAY)
        {
            convert_to_array(array);
        }

        argc = 1 + zend_hash_num_elements(Z_ARRVAL_P(array));
        newargs = (zval *)safe_emalloc(argc, sizeof(zval), 0);
        ZVAL_COPY_VALUE(&newargs[0], z_format);

        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(array), zv)
        {
            ZVAL_COPY_VALUE(&newargs[i], zv);
            i++;
        }
        ZEND_HASH_FOREACH_END();
        args = newargs;
        format_offset = 0;
    }
    if (Z_TYPE(args[format_offset]) != IS_STRING)
    {
        return;
    }
    ns = openrasp_taint_sequence(&args[format_offset]);
    format = Z_STRVAL(args[format_offset]);
    format_len = Z_STRLEN(args[format_offset]);

    currarg = 1;

    while (inpos < Z_STRLEN(args[format_offset]))
    {
        int expprec = 0;
        zval *tmp;

        if (format[inpos] != '%')
        {
            inpos++;
        }
        else if (format[inpos + 1] == '%')
        {
            inpos += 2;
            replace_items.push_back({inpos, 1, 0});
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
                        if (newargs)
                        {
                            efree(newargs);
                        }
                        return;
                    }

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
                    else if (format[inpos] == '\'' && inpos + 1 < format_len)
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
                        if (newargs)
                        {
                            efree(newargs);
                        }
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
                            if (newargs)
                            {
                                efree(newargs);
                            }
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
                if (newargs)
                {
                    efree(newargs);
                }
                return;
            }

            if (format[inpos] == 'l')
            {
                inpos++;
            }
            /* now we expect to find a type specifier */
            tmp = &args[argnum];
            NodeSequence item_ns;
            if (openrasp_taint_possible(tmp))
            {
                item_ns = openrasp_taint_sequence(tmp);
            }
            if (format[inpos] == 's' && Z_TYPE_P(tmp) == IS_STRING && item_ns.taintedSize())
            {
                zend_string *str = zval_get_string(tmp);
                register size_t npad;
                size_t req_size;
                size_t copy_len;

                copy_len = (expprec ? MIN(precision, ZSTR_LEN(str)) : ZSTR_LEN(str));
                npad = (width < copy_len) ? 0 : width - copy_len;
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
                replace_items.push_back({percentage_mark_pos, inpos - percentage_mark_pos + 1, item_ns});

                zend_string_release(str);
            }
            else
            {
                zval function;

                zval retval;
                std::string specifier = "%";
                specifier.append(Z_STRVAL(args[format_offset]) + modifiers_pos, inpos - modifiers_pos + 1);
                zval params[2];
                ZVAL_STRING(&params[0], (char *)specifier.c_str());
                if (use_array)
                {
                    ZVAL_STRING(&function, "vsprintf");
                    array_init(&params[1]);
                    Z_TRY_ADDREF_P(tmp);
                    add_next_index_zval(&params[1], tmp);
                }
                else
                {
                    ZVAL_STRING(&function, "sprintf");
                    params[1] = *tmp;
                }

                if (call_user_function(EG(function_table), nullptr, &function, &retval, 2, params) == SUCCESS &&
                    Z_TYPE(retval) == IS_STRING)
                {
                    replace_items.push_back({percentage_mark_pos, inpos - percentage_mark_pos + 1, Z_STRLEN(retval)});
                }
                if (use_array && Z_TYPE(params[1]) == IS_ARRAY)
                {
                    zval_dtor(&params[1]);
                }
                zval_dtor(&retval);
                zval_ptr_dtor(&params[0]);
                zval_ptr_dtor(&function);
            }
            inpos++;
        }
    }
    auto item = replace_items.rbegin();
    while (item != replace_items.rend())
    {
        ns.erase(item->pos, item->erase_length);
        ns.insert(item->pos, item->insert_ns);
        ++item;
    }
    if (newargs)
    {
        efree(newargs);
    }
}