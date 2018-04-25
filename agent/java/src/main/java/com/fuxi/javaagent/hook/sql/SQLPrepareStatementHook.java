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

package com.fuxi.javaagent.hook.sql;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

import java.util.Arrays;

/**
 * Created by tyy on 18-4-25.
 *
 * sql Prepare 查询 hook 点
 */
public class SQLPrepareStatementHook extends AbstractSqlHook {

    private String className;

    @Override
    public boolean isClassMatched(String className) {

        /* MySQL */
        if ("com/mysql/jdbc/PreparedStatement".equals(className)
                || "com/mysql/cj/jdbc/PreparedStatement".equals(className)) {
            this.type = SQL_TYPE_MYSQL;
            this.exceptions = new String[]{"java/sql/SQLException"};
            this.className = className;
            return true;
        }

        return false;
    }

    @Override
    public String getType() {
        return "sql_prepare";
    }

    @Override
    protected MethodVisitor hookMethod(int access, String name, String desc, String signature, String[] exceptions, MethodVisitor mv) {

        return isExecutableSqlMethod(name, desc) ? new AdviceAdapter(Opcodes.ASM5, mv, access, name, desc) {
            @Override
            protected void onMethodEnter() {
                loadThis();
                getField(Type.getType(className), "originalSql", Type.getType(String.class));
                loadThis();
                push(type);
                invokeStatic(Type.getType(SQLPrepareStatementHook.class),
                        new Method("checkSQL", "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)V"));
            }
        } : mv;

    }

    public boolean isExecutableSqlMethod(String name, String desc) {
        boolean result = false;
        if (name.equals("execute") && Arrays.equals(exceptions, this.exceptions)) {
            if (desc.startsWith("()")) {
                result = true;
            }
        } else if (name.equals("executeUpdate") && Arrays.equals(exceptions, this.exceptions)) {
            if (desc.startsWith("()")) {
                result = true;
            }
        } else if (name.equals("executeQuery") && Arrays.equals(exceptions, this.exceptions)) {
            if (desc.startsWith("()")) {
                result = true;
            }
        } else if (name.equals("executeBatch") && Arrays.equals(exceptions, this.exceptions)) {
            if (desc.startsWith("()")) {
                result = true;
            }
        }
        return result;
    }

    /**
     * SQL语句检测
     *
     * @param stmt sql语句
     */
    public static void checkSQL(String stmt, Object statement, String server) {
        SQLStatementHook.checkSQL(server, statement, stmt);
    }
}
