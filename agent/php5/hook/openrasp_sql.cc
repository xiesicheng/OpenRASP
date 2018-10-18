/*
 * Copyright 2017-2018 Baidu Inc.
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
#include "openrasp_ini.h"
#include "openrasp_v8.h"
#include "openrasp_shared_alloc.h"
#include <string>
#include <map>

extern "C"
{
#include "ext/pdo/php_pdo_driver.h"
#include "zend_ini.h"
}

/**
 * sql connection alarm
 */
static void connection_via_default_username_policy(char *check_message, sql_connection_entry *sql_connection_p TSRMLS_DC)
{
    zval *policy_array = nullptr;
    MAKE_STD_ZVAL(policy_array);
    array_init(policy_array);
    add_assoc_string(policy_array, "message", check_message, 1);
    add_assoc_long(policy_array, "policy_id", 3006);
    zval *connection_params = nullptr;
    MAKE_STD_ZVAL(connection_params);
    array_init(connection_params);
    add_assoc_string(connection_params, "server", sql_connection_p->server, 1);
    add_assoc_string(connection_params, "host", sql_connection_p->host, 1);
    add_assoc_long(connection_params, "port", sql_connection_p->port);
    add_assoc_string(connection_params, "user", sql_connection_p->username, 1);
    add_assoc_zval(policy_array, "params", connection_params);
    policy_info(policy_array TSRMLS_CC);
    zval_ptr_dtor(&policy_array);
}

void slow_query_alarm(int rows TSRMLS_DC)
{
    zval *attack_params = nullptr;
    MAKE_STD_ZVAL(attack_params);
    array_init(attack_params);
    add_assoc_long(attack_params, "query_count",rows);
    zval *plugin_message = nullptr;
    MAKE_STD_ZVAL(plugin_message);
    char *message_str = nullptr;
    spprintf(&message_str, 0, _("SQL slow query detected: selected %d rows, exceeding %d"), rows, OPENRASP_CONFIG(sql.slowquery.min_rows));
    ZVAL_STRING(plugin_message, message_str, 1);
    efree(message_str);
    openrasp_buildin_php_risk_handle(0, SQL_SLOW_QUERY, 100, attack_params, plugin_message TSRMLS_CC);
}

zend_bool check_database_connection_username(INTERNAL_FUNCTION_PARAMETERS, init_connection_t connection_init_func, int enforce_policy)
{
    static const std::multimap<std::string, std::string> database_username_blacklists = {
        {"mysql", "root"},
        {"mssql", "sa"},
        {"pgsql", "postgres"},
        {"oci", "dbsnmp"},
        {"oci", "sysman"},
        {"oci", "system"},
        {"oci", "sys"}};
    sql_connection_entry conn_entry;
    char *check_message = nullptr;
    zend_bool need_block = 0;
    connection_init_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, &conn_entry);
    if (conn_entry.server && conn_entry.username && conn_entry.host)
    {
        auto pos = database_username_blacklists.equal_range(std::string(conn_entry.server));
        while (pos.first != pos.second)
        {
            if (std::string(conn_entry.username) == pos.first->second)
            {
                spprintf(&check_message, 0,
                         _("Database security - Connecting to a %s instance using the high privileged account: %s - (%s:%d)"),
                         conn_entry.server,
                         conn_entry.username,
                         conn_entry.host,
                         conn_entry.port);
                break;
            }
            pos.first++;
        }
        if (check_message)
        {
            if (enforce_policy)
            {
                connection_via_default_username_policy(check_message, &conn_entry TSRMLS_CC);
                need_block = 1;
            }
            else
            {
                if (check_sapi_need_alloc_shm())
                {
                    char *server_host_port = nullptr;
                    int server_host_port_len = spprintf(&server_host_port, 0, "%s-%s:%d", conn_entry.server, conn_entry.host, conn_entry.port);
                    ulong connection_hash = zend_inline_hash_func(server_host_port, server_host_port_len);
                    openrasp_shared_alloc_lock(TSRMLS_C);
                    if (!openrasp_shared_hash_exist(connection_hash, OPENRASP_LOG_G(formatted_date_suffix)))
                    {
                        connection_via_default_username_policy(check_message, &conn_entry TSRMLS_CC);
                    }
                    openrasp_shared_alloc_unlock(TSRMLS_C);
                    efree(server_host_port);
                }
            }
            efree(check_message);
            check_message = nullptr;
        }
    }
    if (conn_entry.host)
    {
        efree(conn_entry.host);
    }
    if (conn_entry.username)
    {
        efree(conn_entry.username);
    }
    return need_block;
}

void sql_type_handler(char *query, int query_len, char *server TSRMLS_DC)
{
    openrasp::Isolate *isolate = OPENRASP_V8_G(isolate);
    if (isolate)
    {
        bool is_block = false;
        {
            v8::HandleScope handle_scope(isolate);
            auto params = v8::Object::New(isolate);
            params->Set(openrasp::NewV8String(isolate, "query"), openrasp::NewV8String(isolate, query, query_len));
            params->Set(openrasp::NewV8String(isolate, "server"), openrasp::NewV8String(isolate, server));
            is_block = isolate->Check(openrasp::NewV8String(isolate, CheckTypeNameMap.at(SQL), 3), params, OPENRASP_CONFIG(plugin.timeout.millis));
        }
        if (is_block)
        {
            handle_block(TSRMLS_C);
        }
    }
}

long fetch_rows_via_user_function(const char *f_name_str, zend_uint param_count, zval *params[] TSRMLS_DC)
{
    zval function_name, retval;
    INIT_ZVAL(function_name);
    ZVAL_STRING(&function_name, f_name_str, 0);
    if (call_user_function(EG(function_table), nullptr, &function_name, &retval, param_count, params TSRMLS_CC) == SUCCESS && Z_TYPE(retval) == IS_LONG)
    {
        return Z_LVAL(retval);
    }
    return 0;
}
