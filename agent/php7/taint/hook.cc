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

/**
 * taint 相关hook点
 */
POST_HOOK_FUNCTION(strval, TAINT);
POST_HOOK_FUNCTION(explode, TAINT);

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