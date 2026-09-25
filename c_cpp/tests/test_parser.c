#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

static int failures = 0;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures += 1;
    }
}

static ONodeList *parse_round_trip(const StringSet *backends, const char *source) {
    OParser parser;
    ONodeList *nodes;
    char *reconstructed;
    parser_init(&parser, source, backends);
    nodes = parser_parse(&parser);
    check(nodes != NULL, parser.error_msg);
    if (nodes == NULL) {
        return NULL;
    }
    reconstructed = reconstruct_source(nodes->items, nodes->len);
    check(reconstructed != NULL && strcmp(reconstructed, source) == 0,
          "source bytes round-trip exactly");
    free(reconstructed);
    return nodes;
}

static void test_opener_boundaries(const StringSet *backends) {
    const char *raw[] = {
        "unknown^(1)_unknown",
        "python_suffix^(1)_python_suffix",
        "python23^(1)_python23",
        "bad-name^(1)_bad-name",
        "unknown[4294967295]^(1)_unknown[4294967295]",
        NULL,
    };
    const char *typed[] = {
        "py^(1)_py", "python^(1)_python", "python2^(1)_python2",
        "custom_2^(1)_custom_2", "python[*]{defer}^(1)_python[*]{defer}",
        NULL,
    };
    size_t index;
    for (index = 0; raw[index] != NULL; index++) {
        ONodeList *nodes = parse_round_trip(backends, raw[index]);
        if (nodes != NULL) {
            check(nodes->len == 1 && nodes->items[0]->tag == ONODE_RAW_TEXT,
                  "unknown and extended identifiers remain raw text");
            onode_list_free(nodes);
        }
    }
    for (index = 0; typed[index] != NULL; index++) {
        ONodeList *nodes = parse_round_trip(backends, typed[index]);
        if (nodes != NULL) {
            check(nodes->len == 1 && nodes->items[0]->tag == ONODE_TYPED_EXPR,
                  "registered names and qualified openers remain typed");
            onode_list_free(nodes);
        }
    }
    {
        ONodeList *nodes = parse_round_trip(backends, "xxpython^(1)_python");
        if (nodes != NULL) {
            check(nodes->len == 2 && nodes->items[0]->tag == ONODE_RAW_TEXT &&
                      nodes->items[1]->tag == ONODE_TYPED_EXPR &&
                      strcmp(nodes->items[1]->data.typed_expr.lang, "python") == 0,
                  "a registered suffix opener is still discovered");
            onode_list_free(nodes);
        }
    }
    {
        OParser parser;
        ONodeList *nodes;
        char *reconstructed;
        parser_init(&parser, "\\python^(1)_python", backends);
        nodes = parser_parse(&parser);
        check(nodes != NULL, "escaped opener parses");
        if (nodes != NULL) {
            for (index = 0; index < nodes->len; index++) {
                check(nodes->items[index]->tag == ONODE_RAW_TEXT,
                      "escaped opener does not become executable");
            }
            reconstructed = reconstruct_source(nodes->items, nodes->len);
            check(reconstructed != NULL && strcmp(reconstructed, "python^(1)_python") == 0,
                  "escaped opener retains its literal spelling");
            free(reconstructed);
            onode_list_free(nodes);
        }
    }
}

static void test_long_identifiers(const StringSet *backends) {
    const size_t length = 1024 * 1024;
    char *source = malloc(length + 64);
    ONodeList *nodes;
    check(source != NULL, "allocate one MiB parser fixture");
    if (source == NULL) {
        return;
    }
    memset(source, 'a', length);
    source[length] = '\0';
    nodes = parse_round_trip(backends, source);
    if (nodes != NULL) {
        check(nodes->len == 1 && nodes->items[0]->tag == ONODE_RAW_TEXT,
              "long plain identifier remains one text node");
        onode_list_free(nodes);
    }
    strcpy(source, "text^(");
    memset(source + 6, 'a', length);
    strcpy(source + 6 + length, ")_text");
    nodes = parse_round_trip(backends, source);
    if (nodes != NULL) {
        check(nodes->len == 1 && nodes->items[0]->tag == ONODE_TYPED_EXPR &&
                  nodes->items[0]->data.typed_expr.body_len == 1 &&
                  strlen(nodes->items[0]->data.typed_expr.body[0]->data.text) == length,
              "long nested text preserves every payload byte");
        onode_list_free(nodes);
    }
    memset(source, 'a', length);
    strcpy(source + length, "python^(1)_python");
    nodes = parse_round_trip(backends, source);
    if (nodes != NULL) {
        check(nodes->len == 2 && nodes->items[1]->tag == ONODE_TYPED_EXPR,
              "long raw prefix cannot hide its registered suffix opener");
        onode_list_free(nodes);
    }
    free(source);
}

static void test_call_lookahead(const StringSet *backends) {
    ONodeList *nodes = parse_round_trip(backends, "plain identifier f($x, g()) trailing");
    if (nodes != NULL) {
        check(nodes->len == 3 && nodes->items[0]->tag == ONODE_RAW_TEXT &&
                  nodes->items[1]->tag == ONODE_CALL &&
                  strcmp(nodes->items[1]->data.call.fn_name, "f") == 0 &&
                  nodes->items[1]->data.call.args_len == 2 &&
                  nodes->items[1]->data.call.args[0]->tag == ONODE_VAR_REF &&
                  nodes->items[1]->data.call.args[1]->tag == ONODE_CALL &&
                  nodes->items[2]->tag == ONODE_RAW_TEXT,
              "raw identifier lookahead preserves calls and nested arguments");
        onode_list_free(nodes);
    }
    nodes = parse_round_trip(backends, "python()");
    if (nodes != NULL) {
        check(nodes->len == 2 && nodes->items[0]->tag == ONODE_RAW_TEXT &&
                  strcmp(nodes->items[0]->data.text, "p") == 0 &&
                  nodes->items[1]->tag == ONODE_CALL &&
                  strcmp(nodes->items[1]->data.call.fn_name, "ython") == 0,
              "a registered call name preserves existing suffix discovery");
        onode_list_free(nodes);
    }
}

int main(void) {
    const char *names[] = {"text", "py", "python", "python2", "custom_2", "bad-name", NULL};
    StringSet *backends = string_set_new();
    size_t index;
    if (backends == NULL) {
        return 1;
    }
    for (index = 0; names[index] != NULL; index++) {
        string_set_add(backends, names[index]);
    }
    test_opener_boundaries(backends);
    test_call_lookahead(backends);
    test_long_identifiers(backends);
    string_set_free(backends);
    if (failures != 0) {
        return 1;
    }
    puts("C17 parser boundaries and one-MiB identifier scaling: PASS");
    return 0;
}
