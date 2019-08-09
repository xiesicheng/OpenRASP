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

#define STR_PAD_LEFT 0
#define STR_PAD_RIGHT 1
#define STR_PAD_BOTH 2

static void trim_taint(zend_string *str, char *what, size_t what_len, int mode, zval *return_value);
static int openrasp_needle_char(zval *needle, char *target);

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
                php_error_docref(NULL, E_WARNING, "Invalid '..'-range, no character to the left of '..'");
                result = FAILURE;
                continue;
            }
            if (input + 2 >= end)
            { /* there is no 'right' char */
                php_error_docref(NULL, E_WARNING, "Invalid '..'-range, no character to the right of '..'");
                result = FAILURE;
                continue;
            }
            if (input[-1] > input[2])
            { /* wrong order */
                php_error_docref(NULL, E_WARNING, "Invalid '..'-range, '..'-range needs to be incrementing");
                result = FAILURE;
                continue;
            }
            /* FIXME: better error (a..b..c is the only left possibility?) */
            php_error_docref(NULL, E_WARNING, "Invalid '..'-range");
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
    trim_taint(str, (what ? ZSTR_VAL(what) : NULL), (what ? ZSTR_LEN(what) : 0), 3, return_value);
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
    trim_taint(str, (what ? ZSTR_VAL(what) : NULL), (what ? ZSTR_LEN(what) : 0), 1, return_value);
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
    trim_taint(str, (what ? ZSTR_VAL(what) : NULL), (what ? ZSTR_LEN(what) : 0), 2, return_value);
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
    zend_string *result = NULL; /* Resulting string */

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
        php_error_docref(NULL, E_WARNING, "needle is not a string or an integer");
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
    char *found = NULL;
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
    char *found = NULL;
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