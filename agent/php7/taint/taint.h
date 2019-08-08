#pragma once

#include "openrasp.h"
#include "node_sequence.h"

using taint::NodeSequence;

#define OPENRASP_TAINT_MAGIC_LENGTH sizeof(unsigned)
#define OPENRASP_TAINT_MAGIC_POSSIBLE 0x6A8FCE84
#define OPENRASP_TAINT_POINTER_LENGTH sizeof(uintptr_t)
#define OPENRASP_TAINT_SUFFIX_LENGTH (OPENRASP_TAINT_POINTER_LENGTH + OPENRASP_TAINT_MAGIC_LENGTH)

#define OPENRASP_OP1_TYPE(opline) (opline->op1_type)
#define OPENRASP_OP2_TYPE(opline) (opline->op2_type)

#if PHP_VERSION_ID < 70100
#define OPENRASP_RET_USED(opline) (!((opline)->result_type & EXT_TYPE_UNUSED))
#define OPENRASP_ISERR(var) (var == &EG(error_zval))
#define OPENRASP_ERR_ZVAL(var) (var = &EG(error_zval))
#else
#define OPENRASP_RET_USED(opline) ((opline)->result_type != IS_UNUSED)
#define OPENRASP_ISERR(var) (Z_ISERROR_P(var))
#define OPENRASP_ERR_ZVAL(var) (ZVAL_ERROR(var))
#endif

typedef zval *openrasp_free_op;

void str_unchanege_taint(zval *src, zval *dest);
void str_unchanege_taint(zend_string *zs_src, zval *dest);
// void openrasp_taint_deep_copy(zval *source, zval *target);
void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource, std::function<bool(char *key)> filter = nullptr);
int openrasp_concat_handler(zend_execute_data *execute_data);
int openrasp_assign_concat_handler(zend_execute_data *execute_data);
int openrasp_repo_end_handler(zend_execute_data *execute_data);

void openrasp_taint_mark(zval *zv, NodeSequence *ptr);
bool openrasp_taint_possible(zval *zv);
bool openrasp_taint_possible(zend_string *zs);
NodeSequence openrasp_taint_sequence(zval *zv);
NodeSequence openrasp_taint_sequence(zend_string *zs);
PHP_FUNCTION(taint_dump);