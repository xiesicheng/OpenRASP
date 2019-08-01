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
#define TAINT_RET_USED(opline) (!((opline)->result_type & EXT_TYPE_UNUSED))
#define TAINT_ISERR(var) (var == &EG(error_zval))
#define TAINT_ERR_ZVAL(var) (var = &EG(error_zval))
#else
#define TAINT_RET_USED(opline) ((opline)->result_type != IS_UNUSED)
#define TAINT_ISERR(var) (Z_ISERROR_P(var))
#define TAINT_ERR_ZVAL(var) (ZVAL_ERROR(var))
#endif

typedef zval *openrasp_free_op;

// void str_unchanege_taint(zval *src, zval *dest);
// void openrasp_taint_deep_copy(zval *source, zval *target);
void openrasp_taint_mark_strings(zval *symbol_table, std::string varsSource, std::function<bool(char *key)> filter = nullptr);
int openrasp_concat_handler(zend_execute_data *execute_data);
// int openrasp_assign_concat_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_add_char_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_assign_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_add_var_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_add_string_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_assign_ref_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_qm_assign_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_qm_assign_var_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_send_var_handler(ZEND_OPCODE_HANDLER_ARGS);
// int openrasp_send_ref_handler(ZEND_OPCODE_HANDLER_ARGS);

void openrasp_taint_mark(zval *zv, NodeSequence *ptr);
bool openrasp_taint_possible(zval *zv);
NodeSequence openrasp_taint_sequence(zval *zv);
PHP_FUNCTION(taint_dump);