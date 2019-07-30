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
#include "openrasp_v8.h"
#include "agent/shared_config_manager.h"

/**
 * command相关hook点
 */
PRE_HOOK_FUNCTION(passthru, COMMAND);
PRE_HOOK_FUNCTION(system, COMMAND);
PRE_HOOK_FUNCTION(exec, COMMAND);
PRE_HOOK_FUNCTION(shell_exec, COMMAND);
PRE_HOOK_FUNCTION(proc_open, COMMAND);
PRE_HOOK_FUNCTION(popen, COMMAND);
PRE_HOOK_FUNCTION(pcntl_exec, COMMAND);

PRE_HOOK_FUNCTION(passthru, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(system, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(exec, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(shell_exec, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(proc_open, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(popen, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(pcntl_exec, WEBSHELL_COMMAND);
PRE_HOOK_FUNCTION(assert, EVAL);
PRE_HOOK_FUNCTION(assert, WEBSHELL_EVAL);

static void plugin_command_check(zval *z_command TSRMLS_DC, zval *z_arg = nullptr);

static void check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **command;
    int argc = MIN(1, ZEND_NUM_ARGS());
    if (argc == 1 && zend_get_parameters_ex(argc, &command) == SUCCESS && openrasp_zval_in_request(*command TSRMLS_CC))
    {
        zval *attack_params = NULL;
        MAKE_STD_ZVAL(attack_params);
        array_init(attack_params);
        add_assoc_zval(attack_params, "command", *command);
        Z_ADDREF_PP(command);
        zval *plugin_message = NULL;
        MAKE_STD_ZVAL(plugin_message);
        ZVAL_STRING(plugin_message, _("WebShell activity - Detected command execution backdoor"), 1);
        OpenRASPActionType action = openrasp::scm->get_buildin_check_action(check_type);
        openrasp_buildin_php_risk_handle(action, check_type, 100, attack_params, plugin_message TSRMLS_CC);
    }
}

void plugin_command_check(zval *z_command TSRMLS_DC, zval *z_arg)
{
    openrasp::Isolate *isolate = OPENRASP_V8_G(isolate);
    if (nullptr != z_command &&
        Z_TYPE_P(z_command) == IS_STRING &&
        Z_STRVAL_P(z_command) != nullptr &&
        Z_STRLEN_P(z_command) &&
        isolate)
    {
        std::string command(Z_STRVAL_P(z_command));
        if (nullptr != z_arg)
        {
            if (IS_STRING == Z_TYPE_P(z_arg) &&
                Z_STRLEN_P(z_arg))
            {
                command.append(Z_STRVAL_P(z_arg), Z_STRLEN_P(z_arg));
            }
            else if (IS_ARRAY == Z_TYPE_P(z_arg))
            {
                zval function;
                INIT_ZVAL(function);
                ZVAL_STRING(&function, "implode", 0);
                zval retval;
                zval *z_glue = nullptr;
                MAKE_STD_ZVAL(z_glue);
                ZVAL_STRING(z_glue, " ", 1);
                zval *params[2];
                params[0] = z_glue;
                params[1] = z_arg;
                if (call_user_function(EG(function_table), nullptr, &function, &retval, 2, params TSRMLS_CC) == SUCCESS &&
                    Z_TYPE(retval) == IS_STRING)
                {
                    command.append(" ").append(Z_STRVAL(retval), Z_STRLEN(retval));
                    zval_dtor(&retval);
                }
                zval_ptr_dtor(&z_glue);
            }
        }
        openrasp::CheckResult check_result = openrasp::CheckResult::kCache;
        {
            v8::HandleScope handle_scope(isolate);
            auto params = v8::Object::New(isolate);
            params->Set(openrasp::NewV8String(isolate, "command"), openrasp::NewV8String(isolate, command));
            check_result = Check(isolate, openrasp::NewV8String(isolate, get_check_type_name(COMMAND)), params, OPENRASP_CONFIG(plugin.timeout.millis));
        }
        if (check_result == openrasp::CheckResult::kBlock)
        {
            handle_block(TSRMLS_C);
        }
    }
}

static void openrasp_exec_ex(INTERNAL_FUNCTION_PARAMETERS, int mode)
{
    zval *z_cmd;
    zval *ret_code = NULL, *ret_array = NULL;
    int ret;
    if (mode)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|z/", &z_cmd, &ret_code) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|z/z/", &z_cmd, &ret_array, &ret_code) == FAILURE)
        {
            return;
        }
    }
    plugin_command_check(z_cmd TSRMLS_CC);
}

void pre_global_passthru_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_passthru_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    openrasp_exec_ex(INTERNAL_FUNCTION_PARAM_PASSTHRU, 3);
}

void pre_global_system_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_system_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    openrasp_exec_ex(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

void pre_global_exec_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_exec_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    openrasp_exec_ex(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

void pre_global_shell_exec_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_shell_exec_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *z_command;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z_command) == FAILURE)
    {
        return;
    }
    plugin_command_check(z_command TSRMLS_CC);
}

void pre_global_proc_open_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_proc_open_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *z_command;
    zval *descriptorspec;
    zval *pipes;
    zval *cwd = NULL;
    zval *environment = NULL;
    zval *other_options = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zaz|z!z!z!", &z_command,
                              &descriptorspec, &pipes, &cwd, &environment,
                              &other_options) == FAILURE)
    {
        return;
    }
    plugin_command_check(z_command TSRMLS_CC);
}

void pre_global_popen_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_popen_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *z_command;
    char *mode;
    int mode_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &z_command, &mode, &mode_len) == FAILURE)
    {
        return;
    }
    plugin_command_check(z_command TSRMLS_CC);
}

void pre_global_pcntl_exec_WEBSHELL_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    check_command_in_gpc(OPENRASP_INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

void pre_global_pcntl_exec_COMMAND(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval *args = NULL, *envs = NULL;
    zval *z_path;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|aa", &z_path, &args, &envs) == FAILURE)
    {
        return;
    }

    plugin_command_check(z_path TSRMLS_CC, args);
}

void pre_global_assert_WEBSHELL_EVAL(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **assertion;
    int description_len = 0;
    char *description = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|s", &assertion, &description, &description_len) == FAILURE)
    {
        return;
    }
    // if (Z_TYPE_PP(assertion) == IS_STRING)
    {
        if (openrasp_zval_in_request(*assertion TSRMLS_CC))
        {
            zval *attack_params;
            MAKE_STD_ZVAL(attack_params);
            array_init(attack_params);
            add_assoc_zval(attack_params, "eval", *assertion);
            Z_ADDREF_PP(assertion);
            zval *plugin_message = NULL;
            MAKE_STD_ZVAL(plugin_message);
            ZVAL_STRING(plugin_message, _("WebShell activity - Detected China Chopper (assert method)"), 1);
            OpenRASPActionType action = openrasp::scm->get_buildin_check_action(check_type);
            openrasp_buildin_php_risk_handle(action, check_type, 100, attack_params, plugin_message TSRMLS_CC);
        }
    }
}

void pre_global_assert_EVAL(OPENRASP_INTERNAL_FUNCTION_PARAMETERS)
{
    zval **assertion;
    int description_len = 0;
    char *description = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|s", &assertion, &description, &description_len) == FAILURE)
    {
        return;
    }
    openrasp::Isolate *isolate = OPENRASP_V8_G(isolate);
    if (isolate && Z_TYPE_PP(assertion) == IS_STRING)
    {
        openrasp::CheckResult check_result = openrasp::CheckResult::kCache;
        {
            v8::HandleScope handle_scope(isolate);
            auto params = v8::Object::New(isolate);
            params->Set(openrasp::NewV8String(isolate, "code"), openrasp::NewV8String(isolate, Z_STRVAL_PP(assertion), Z_STRLEN_PP(assertion)));
            params->Set(openrasp::NewV8String(isolate, "function"), openrasp::NewV8String(isolate, "assert"));
            check_result = Check(isolate, openrasp::NewV8String(isolate, get_check_type_name(check_type)), params, OPENRASP_CONFIG(plugin.timeout.millis));
        }
        if (check_result == openrasp::CheckResult::kBlock)
        {
            handle_block(TSRMLS_C);
        }
    }
}