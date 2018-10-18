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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern "C"
{
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_openrasp.h"
#include "php_scandir.h"
}
#include <sstream>
#include <fstream>
#include "openrasp_v8.h"
#include "openrasp_ini.h"
#ifdef HAVE_OPENRASP_REMOTE_MANAGER
#include "agent/openrasp_agent_manager.h"
#endif

namespace openrasp
{
openrasp_v8_process_globals process_globals;

static inline void load_plugins(TSRMLS_D)
{
    std::vector<openrasp_v8_js_src> plugin_src_list;
    std::string plugin_path(std::string(openrasp_ini.root_dir) + DEFAULT_SLASH + std::string("plugins"));
    dirent **ent = nullptr;
    int n_plugin = php_scandir(plugin_path.c_str(), &ent, nullptr, nullptr);
    for (int i = 0; i < n_plugin; i++)
    {
        const char *p = strrchr(ent[i]->d_name, '.');
        if (p != nullptr && strcasecmp(p, ".js") == 0)
        {
            std::string filename(ent[i]->d_name);
            std::string filepath(plugin_path + DEFAULT_SLASH + filename);
            struct stat sb;
            if (VCWD_STAT(filepath.c_str(), &sb) == 0 && (sb.st_mode & S_IFREG) != 0)
            {
                std::ifstream file(filepath);
                std::streampos beg = file.tellg();
                file.seekg(0, std::ios::end);
                std::streampos end = file.tellg();
                file.seekg(0, std::ios::beg);
                // plugin file size limitation: 10 MB
                if (10 * 1024 * 1024 >= end - beg)
                {
                    std::string source((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
                    plugin_src_list.emplace_back(openrasp_v8_js_src{filename, source});
                }
                else
                {
                    openrasp_error(E_WARNING, CONFIG_ERROR, _("Ignored Javascript plugin file '%s', as it exceeds 10 MB in file size."), filename.c_str());
                }
            }
        }
        free(ent[i]);
    }
    free(ent);
    process_globals.plugin_src_list = plugin_src_list;
}

} // namespace openrasp

using namespace openrasp;

ZEND_DECLARE_MODULE_GLOBALS(openrasp_v8)

PHP_GINIT_FUNCTION(openrasp_v8)
{
#ifdef ZTS
    new (openrasp_v8_globals) _zend_openrasp_v8_globals;
#endif
}

PHP_GSHUTDOWN_FUNCTION(openrasp_v8)
{
    if (openrasp_v8_globals->isolate)
    {
        openrasp_v8_globals->isolate->Dispose();
        openrasp_v8_globals->isolate = nullptr;
    }
#ifdef ZTS
    openrasp_v8_globals->~_zend_openrasp_v8_globals();
#endif
}

PHP_MINIT_FUNCTION(openrasp_v8)
{
    ZEND_INIT_MODULE_GLOBALS(openrasp_v8, PHP_GINIT(openrasp_v8), PHP_GSHUTDOWN(openrasp_v8));

    // It can be called multiple times,
    // but intern code initializes v8 only once
    v8::V8::Initialize();

    load_plugins(TSRMLS_C);

    if (!process_globals.snapshot_blob)
    {
        Platform::Initialize();
        Snapshot *snapshot = new Snapshot(process_globals.plugin_config, process_globals.plugin_src_list);
        Platform::Shutdown();
        if (!snapshot->IsOk())
        {
            delete snapshot;
        }
        else
        {
            process_globals.snapshot_blob = snapshot;
        }
    }
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(openrasp_v8)
{
    ZEND_SHUTDOWN_MODULE_GLOBALS(openrasp_v8, PHP_GSHUTDOWN(openrasp_v8));

    // Disposing v8 is permanent, it cannot be reinitialized,
    // it should generally not be necessary to dispose v8 before exiting a process,
    // so skip this step for module graceful reload
    // v8::V8::Dispose();
    Platform::Shutdown();
    delete process_globals.snapshot_blob;
    process_globals.snapshot_blob = nullptr;

    return SUCCESS;
}

PHP_RINIT_FUNCTION(openrasp_v8)
{
#ifdef HAVE_OPENRASP_REMOTE_MANAGER
    if (openrasp_ini.remote_management_enable && oam != nullptr)
    {
        uint64_t timestamp = oam->get_plugin_update_timestamp();
        if (!process_globals.snapshot_blob ||
            process_globals.snapshot_blob->IsExpired(timestamp))
        {
            std::unique_lock<std::mutex> lock(process_globals.mtx, std::try_to_lock);
            if (lock &&
                (!process_globals.snapshot_blob ||
                 process_globals.snapshot_blob->IsExpired(timestamp)))
            {
                std::string filename = std::string(openrasp_ini.root_dir) + DEFAULT_SLASH + std::string("snapshot.dat");
                Snapshot *blob = new Snapshot(filename, timestamp);
                if (!blob->IsOk())
                {
                    delete blob;
                }
                else
                {
                    delete process_globals.snapshot_blob;
                    process_globals.snapshot_blob = blob;
                }
                process_globals.mtx.unlock();
            }
        }
    }
#endif
    if (process_globals.snapshot_blob)
    {
        if (!OPENRASP_V8_G(isolate) || OPENRASP_V8_G(isolate)->IsExpired(process_globals.snapshot_blob->timestamp))
        {
            std::unique_lock<std::mutex> lock(process_globals.mtx, std::try_to_lock);
            if (lock)
            {
                if (OPENRASP_V8_G(isolate))
                {
                    OPENRASP_V8_G(isolate)->Dispose();
                }
                Platform::Initialize();
                OPENRASP_V8_G(isolate) = Isolate::New(process_globals.snapshot_blob);
            }
        }
    }
    return SUCCESS;
}