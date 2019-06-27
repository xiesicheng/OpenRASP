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

/**
 * taint 相关hook点
 */
POST_HOOK_FUNCTION(strval, TAINT);

void post_global_strval_TAINT(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **arg;
    int tainted = 0;

    if (ZEND_NUM_ARGS() != 1 || zend_get_parameters_ex(1, &arg) == FAILURE)
    {
        WRONG_PARAM_COUNT;
    }

    if (Z_TYPE_PP(arg) == IS_STRING && OPENRASP_TAINT_POSSIBLE(*arg))
    {
        return;
    }
}