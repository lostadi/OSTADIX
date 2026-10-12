#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eval.h"
#include "parser.h"
#include "value.h"

static int failures = 0;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static OValue *evaluate(OEvaluator *evaluator, const StringSet *backends,
                        const char *source) {
    OParser parser;
    ONodeList *nodes;
    OValue *value;

    parser_init(&parser, source, backends);
    nodes = parser_parse(&parser);
    if (!nodes) {
        fprintf(stderr, "FAIL: parse before evaluation: %s\n", parser.error_msg);
        failures++;
        return NULL;
    }
    value = olang_evaluator_eval_document(evaluator, nodes);
    onode_list_free(nodes);
    return value;
}

static int string_equals(const OValue *value, const char *expected) {
    return value && value->tag == OVAL_STR &&
           strcmp(value->data.str_val, expected) == 0;
}

static void expect_string(OEvaluator *evaluator, const StringSet *backends,
                          const char *source, const char *expected,
                          const char *message) {
    OValue *value = evaluate(evaluator, backends, source);
    if (!string_equals(value, expected)) {
        char *actual = value ? oval_to_json(value) : NULL;
        fprintf(stderr, "expected %s, got %s\n", expected, actual ? actual : "<null>");
        free(actual);
    }
    check(string_equals(value, expected), message);
    check(!olang_evaluator_had_error(evaluator), "successful O evaluation has no hidden error");
    oval_release(value);
}

static void test_bindings_and_scopes(OEvaluator *evaluator,
                                     const StringSet *backends) {
    OValue *value;

    value = evaluate(evaluator, backends, "let value = text^(enclosing)_text");
    check(value && value->tag == OVAL_NULL && !olang_evaluator_had_error(evaluator),
          "an enclosing document binding is available to O blocks");
    oval_release(value);

    value = evaluate(evaluator, backends, "O^( let unused = text^(bound)_text )_O");
    check(value && value->tag == OVAL_NULL && !olang_evaluator_had_error(evaluator),
          "bindings alone do not produce an O sequence result");
    oval_release(value);
    expect_string(evaluator, backends,
                  "O^( text^(result)_text let unused = text^(bound)_text )_O",
                  "result", "a final binding preserves the prior expression result");

    expect_string(evaluator, backends,
                  "O^( let local = text^($value)_text $local)_O",
                  "enclosing", "O bindings can read the enclosing scope");
    expect_string(evaluator, backends,
                  "O^( let value = text^(local)_text $value)_O",
                  "local", "a returned binding survives release of the O scope");
    expect_string(evaluator, backends, "text^($value)_text", "enclosing",
                  "O shadowing leaves the enclosing binding unchanged");
    expect_string(evaluator, backends,
                  "O^( let value = text^(parent)_text "
                  "O^(text^($value)_text)_O)_O",
                  "parent", "nested O blocks inherit their parent bindings");
    expect_string(evaluator, backends,
                  "O^( let value = text^(parent)_text "
                  "O^( let value = text^(child)_text $value)_O "
                  "text^($value)_text)_O",
                  "parent", "nested shadowing is restored before the next parent expression");
    expect_string(evaluator, backends,
                  "O^( O^( let private = text^(hidden)_text $private)_O "
                  "text^($private)_text)_O",
                  "$private", "bindings created by a child do not leak to its parent");
    expect_string(evaluator, backends, "text^($local)_text", "$local",
                  "bindings created by an O root do not leak to later documents");

    value = evaluate(evaluator, backends,
                     "O^( let value = text^(failed)_text "
                     "now($value))_O");
    check(value && value->tag == OVAL_NULL && olang_evaluator_had_error(evaluator),
          "a failed child causes the O document to fail");
    oval_release(value);
    expect_string(evaluator, backends, "text^($value)_text", "enclosing",
                  "failed O evaluation also restores its enclosing scope");
}

static void test_source_order_and_result(OEvaluator *evaluator,
                                          const StringSet *backends) {
    OValue *value = evaluate(
        evaluator, backends,
        "O^(\n"
        "python[81]^(events = []; events.append('before'))_python[81]\n"
        "let answer = python[81]^(events.append('binding'); __oval_result__ = 42)_python[81]\n"
        "python[81]^(events.append('after'); __oval_result__ = events)_python[81]\n"
        ")_O");
    check(value && value->tag == OVAL_LIST && value->data.list.len == 3,
          "O bindings and foreign expressions each execute once");
    if (value && value->tag == OVAL_LIST && value->data.list.len == 3) {
        check(string_equals(value->data.list.items[0], "before") &&
              string_equals(value->data.list.items[1], "binding") &&
              string_equals(value->data.list.items[2], "after"),
              "O effects preserve authored order across let bindings");
    }
    check(!olang_evaluator_had_error(evaluator), "ordered foreign evaluations completed cleanly");
    oval_release(value);

    expect_string(evaluator, backends,
                  "O^(\n text^(retained)_text\n python^(pass)_python\n )_O",
                  "retained", "null results and formatting preserve the last non-null O result");
}

int main(int argc, char **argv) {
    StringSet *backends;
    OEvaluator *evaluator;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <shim-dir>\n", argv[0]);
        return 2;
    }
    backends = string_set_new();
    evaluator = olang_evaluator_new(argv[1]);
    check(backends && evaluator, "test evaluator and backend set are allocated");
    if (backends && evaluator) {
        string_set_add(backends, "O");
        string_set_add(backends, "text");
        string_set_add(backends, "python");
        check(olang_evaluator_set_registered(evaluator, backends), "test backends are registered");
        test_bindings_and_scopes(evaluator, backends);
        test_source_order_and_result(evaluator, backends);
    }
    olang_evaluator_free(evaluator);
    string_set_free(backends);
    if (failures) {
        fprintf(stderr, "%d O sequencing checks failed\n", failures);
        return 1;
    }
    puts("PASS: C17 O bindings, source order, lexical scopes, and last non-null results");
    return 0;
}
