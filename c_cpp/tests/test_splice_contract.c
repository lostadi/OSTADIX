/* A hand-built/mutated AST must fail before an earlier real Python producer.
   The check itself invokes no guest runtime. */
#include "parser.h"
#include "eval.h"
#include "backends.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if(argc != 3) return 2;
    char source[4096];
    int size=snprintf(source,sizeof(source),
        "python^(__import__('pathlib').Path('%s').write_text('effect'))_python\n"
        "sql^(SELECT $payload AS who;)_sql",argv[1]);
    if(size < 0 || (size_t)size >= sizeof(source)) return 2;
    StringSet *backends=olang_default_backends();
    OParser parser;parser_init(&parser,source,backends);
    ONodeList *nodes=parser_parse(&parser);
    if(!nodes) {fprintf(stderr,"unexpected parse error: %s\n",parser.error_msg);return 3;}
    ONode *sql=NULL;
    for(size_t i=0;i<nodes->len;i++) if(nodes->items[i]->tag==ONODE_TYPED_EXPR &&
        !strcmp(nodes->items[i]->data.typed_expr.lang,"sql")) sql=nodes->items[i];
    if(!sql || sql->data.typed_expr.body_len != 3) return 4;
    free(sql->data.typed_expr.body[0]->data.text);
    free(sql->data.typed_expr.body[2]->data.text);
    sql->data.typed_expr.body[0]->data.text=strdup("SELECT '");
    sql->data.typed_expr.body[2]->data.text=strdup("' AS who;");
    OEvaluator *evaluator=olang_evaluator_new(argv[2]);
    olang_evaluator_set_registered(evaluator,backends);
    OValue *value=olang_evaluator_eval_document(evaluator,nodes);
    int failed=!olang_evaluator_had_error(evaluator) || access(argv[1],F_OK)==0;
    oval_release(value);olang_evaluator_free(evaluator);onode_list_free(nodes);string_set_free(backends);
    return failed;
}
