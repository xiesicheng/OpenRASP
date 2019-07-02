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

/**
 * taint 相关hook点
 */
POST_HOOK_FUNCTION(strval, TAINT);
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

void post_global_strval_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **arg;

    if (ZEND_NUM_ARGS() != 1 || zend_get_parameters_ex(1, &arg) == FAILURE)
    {
        WRONG_PARAM_COUNT;
    }

    if (Z_TYPE_PP(arg) == IS_STRING &&
        OPENRASP_TAINT_POSSIBLE(*arg) &&
        IS_STRING == Z_TYPE_P(return_value) &&
        Z_STRLEN_P(return_value))
    {
        Z_STRVAL_P(return_value) = (char *)erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + OPENRASP_TAINT_SUFFIX_LENGTH);
        OPENRASP_TAINT_MARK(return_value, new NodeSequence(OPENRASP_TAINT_SEQUENCE(*arg)));
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