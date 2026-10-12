;;; test_emacs.el --- Real Emacs fontification regressions -*- lexical-binding: t; -*-
(require 'ert)
(require 'cl-lib)

(defmacro ostadix-test-buffer (source &rest body)
  (declare (indent 1))
  `(with-temp-buffer
     (insert ,source)
     (ostadix-mode)
     (font-lock-ensure)
     ,@body))

(defun ostadix-test-property (needle property)
  (goto-char (point-min))
  (search-forward needle)
  (get-text-property (- (point) (length needle)) property))

(defconst ostadix-test-native-samples
  '(("host" "let value = 42" "let")
    ("python" "def function():\n  return 42" "def")
    ("javascript" "function value() { return 42; }" "function")
    ("shell" "if true; then echo value; fi" "if")
    ("html" "<div class=\"value\">hello</div>" "div")
    ("sql" "SELECT value FROM table_name" "SELECT")
    ("rust" "fn value() -> i32 { 42 }" "fn")
    ("cpp" "class Value {};" "class")
    ("csharp" "public class Value {}" "public")
    ("c" "int value = 42;" "int")
    ("java" "public class Value {}" "public")
    ("ruby" "def value\n  42\nend" "def")
    ("lisp" "(defun value () 42)" "defun")
    ("racket" "(define value 42)" "define")
    ("nix" "let value = 42; in value" "let")
    ("markdown" "# Heading\n\n**bold**" "Heading")
    ("latex" "\\section{Heading}" "section")
    ("text" "plain words" "plain")
    ("haskell" "module Value where\nvalue = 42" "module")
    ("ocaml" "let value = 42" "let")
    ("webassembly" "(module (func (result i32) i32.const 42))" "module")
    ("matlab" "function value = example()\nvalue = 42;\nend" "function")
    ("mathematica" "Module[{value = 42}, value]" "Module")))

(defmacro ostadix-test-without-engines (&rest body)
  (declare (indent 0))
  ;; Rebinding primitives in a native-compiled Emacs must not itself build GCC
  ;; trampolines.  This isolates the test guard from the fontification behavior.
  `(let ((native-comp-enable-subr-trampolines nil))
     (cl-letf (((symbol-function 'make-process) (lambda (&rest _) (error "Started a runtime")))
            ((symbol-function 'start-process) (lambda (&rest _) (error "Started a runtime")))
            ((symbol-function 'start-file-process) (lambda (&rest _) (error "Started a runtime")))
            ((symbol-function 'call-process) (lambda (&rest _) (error "Executed a runtime")))
            ((symbol-function 'call-process-region) (lambda (&rest _) (error "Executed a runtime")))
            ((symbol-function 'process-file) (lambda (&rest _) (error "Executed a runtime")))
            ((symbol-function 'make-network-process) (lambda (&rest _) (error "Started networking"))))
       ,@body)))

(ert-deftest ostadix-all-native-grammars-fontify-without-starting-engines ()
  (ostadix-test-without-engines
    (dolist (sample ostadix-test-native-samples)
      (let* ((key (car sample))
             (language (cl-find key ostadix--languages :key #'car :test #'equal))
             (tag (car (cadr language))))
        (ostadix-test-buffer (concat "O^(\n" tag "^(\n" (nth 1 sample) "\n)_" tag "\n)_O")
          (should-not ostadix-missing-language-modes)
          (should (equal (ostadix-test-property (nth 2 sample) 'ostadix-language) key))
          (if (equal key "text")
              (should-not (ostadix-test-property (nth 2 sample) 'face))
            (should (ostadix-test-property (nth 2 sample) 'face))))))))

(ert-deftest ostadix-installed-mode-definitions-take-precedence ()
  (let ((old (symbol-function 'rust-mode))
        (mode-file (expand-file-name "tools/syntax/emacs/ostadix-mode.el"
                                     (getenv "OSTADIX_TEST_ROOT"))))
    (unwind-protect
        (progn
          (fset 'rust-mode (lambda () (setq major-mode 'user-rust-mode)))
          (let ((definition (symbol-function 'rust-mode)))
            (load mode-file nil t)
            (should (eq definition (symbol-function 'rust-mode)))))
      (fset 'rust-mode old))))

(ert-deftest ostadix-installed-library-path-takes-precedence ()
  (let ((old (symbol-function 'rust-mode))
        (directory (make-temp-file "ostadix-user-mode-" t)))
    (unwind-protect
        (let ((load-path (cons directory load-path)))
          (with-temp-file (expand-file-name "rust-mode.el" directory)
            (insert "(defun rust-mode () (setq major-mode 'user-rust-mode))\n"))
          (fmakunbound 'rust-mode)
          (load (expand-file-name "tools/syntax/emacs/ostadix-mode.el"
                                  (getenv "OSTADIX_TEST_ROOT")) nil t)
          (with-temp-buffer
            (rust-mode)
            (should (eq major-mode 'user-rust-mode))))
      (fset 'rust-mode old)
      (delete-directory directory t))))

(ert-deftest ostadix-catalog-all-tags-and-header-forms ()
  (dolist (language ostadix--languages)
    (dolist (tag (cadr language))
      (dolist (suffix '("" "[*]" "[17]" "{process}" "[17]{process,cap=one[]:/a}"))
        (let ((header (concat tag suffix)))
          (ostadix-test-buffer (concat "O^(\n" header "^(\nprobe_body\n)_" header "\n)_O")
            (should (equal (ostadix-test-property "probe_body" 'ostadix-language)
                           (car language)))
            (should (eq (ostadix-test-property (concat ")_" header) 'face)
                        'font-lock-preprocessor-face))))))))

(ert-deftest ostadix-nested-comments-strings-and-parent-restoration ()
  (ostadix-test-buffer
      (concat "O^(\npython[7]{process}^(\n"
              "def before():\n"
              "  value = \"rust^(fn child() {42})_rust\"\n"
              "  # sql^(SELECT 42)_sql\n"
              "  return 9\n"
              ")_python[8]{process}\n"
              "def after_wrong_closer(): pass\n"
              ")_python[7]{process}\n"
              "let host_after = text^(done)_text\n)_O")
    (should (equal (ostadix-test-property "fn child" 'ostadix-language) "rust"))
    (should (equal (ostadix-test-property "SELECT" 'ostadix-language) "sql"))
    (should (equal (ostadix-test-property "return 9" 'ostadix-language) "python"))
    (should (eq (ostadix-test-property "return" 'face) 'font-lock-keyword-face))
    (should (equal (ostadix-test-property "after_wrong_closer" 'ostadix-language) "python"))
    (should (equal (ostadix-test-property "host_after" 'ostadix-language) "host"))))

(ert-deftest ostadix-recursive-same-language-and-alias-closers ()
  (ostadix-test-buffer
      (concat "O^(\npy^(\npython^(inner_python)_python\n"
              ")_python\nstill_alias_python\n)_py[1]\nstill_bare_python\n"
              ")_py\ntext^(outside)_text\n)_O")
    (should (equal (ostadix-test-property "inner_python" 'ostadix-language) "python"))
    (should (equal (ostadix-test-property "still_alias_python" 'ostadix-language) "python"))
    (should (equal (ostadix-test-property "still_bare_python" 'ostadix-language) "python"))
    (should (equal (ostadix-test-property "outside" 'ostadix-language) "text"))))

(ert-deftest ostadix-escapes-and-host-comments-are-literal ()
  (ostadix-test-buffer
      (concat "O^(\n# python^(comment_literal)_python $comment_var\n"
              "text^(\\python^(escaped_literal)_python \\$literal $splice)_text\n)_O")
    (should (equal (ostadix-test-property "comment_literal" 'ostadix-language) "host"))
    (should (eq (ostadix-test-property "$comment_var" 'face) 'font-lock-comment-face))
    (should (equal (ostadix-test-property "escaped_literal" 'ostadix-language) "text"))
    (should (eq (ostadix-test-property "\\python^(" 'face) 'font-lock-escape-face))
    (should (eq (ostadix-test-property "$splice" 'face) 'font-lock-variable-name-face))))

(ert-deftest ostadix-edit-invalidates-structural-state ()
  (ostadix-test-buffer "O^(\npython^(body)_python\n)_O"
    (should (equal (ostadix-test-property "body" 'ostadix-language) "python"))
    (erase-buffer)
    (insert "O^(\ntext^(body)_text\n)_O")
    (font-lock-flush)
    (font-lock-ensure)
    (should (equal (ostadix-test-property "body" 'ostadix-language) "text"))))

(ert-deftest ostadix-missing-modes-have-visible-specific-fallbacks ()
  (let ((ostadix--languages '(("rust" ("rust") ostadix-nonexistent-mode "fn let mut"))))
    ;; Scan metadata constants still accept rust; the fallback mode is deliberately absent.
    (ostadix-test-buffer "rust^(fn function() {42})_rust"
      (should (memq 'ostadix-nonexistent-mode ostadix-missing-language-modes))
      (should (equal (alist-get 'ostadix-nonexistent-mode ostadix-language-mode-errors)
                     "Major mode `ostadix-nonexistent-mode' is unavailable"))
      (should (eq (ostadix-test-property "fn" 'face) 'font-lock-keyword-face)))))

(ert-deftest ostadix-mode-errors-preserve-source-and-continue-other-bodies ()
  (let ((calls 0)
        (source "O^(rust^(fn value() {42})_rust\npython^(def following(): pass)_python)_O"))
    (cl-letf (((symbol-function 'rust-mode)
               (lambda ()
                 (cl-incf calls)
                 (erase-buffer)
                 (insert "broken mode changed its body")
                 (put-text-property (point-min) (point-max) 'face 'font-lock-warning-face)
                 (narrow-to-region 1 4)
                 (error "Selected user Rust mode requires unavailable API"))))
      (ostadix-test-buffer source
        (should (= calls 1))
        (should (equal (buffer-substring-no-properties (point-min) (point-max)) source))
        (should (equal ostadix-missing-language-modes '(rust-mode)))
        (should (equal (alist-get 'rust-mode ostadix-language-mode-errors)
                       "Selected user Rust mode requires unavailable API"))
        (should (eq (ostadix-test-property "fn" 'face) 'font-lock-keyword-face))
        (should-not (ostadix-test-property "value" 'face))
        (should (eq (ostadix-test-property "42" 'face) 'font-lock-constant-face))
        (should (eq (ostadix-test-property "def" 'face) 'font-lock-keyword-face))
        (should (equal (ostadix-test-property "following" 'ostadix-language) "python"))
        ;; A new document scan clears stale diagnostics instead of retaining an
        ;; error for a language that is no longer present.
        (erase-buffer)
        (insert "O^(text^(plain)_text)_O")
        (font-lock-flush)
        (font-lock-ensure)
        (should-not ostadix-missing-language-modes)
        (should-not ostadix-language-mode-errors)))))

(ert-deftest ostadix-native-font-lock-errors-clear-partial-faces ()
  (cl-letf (((symbol-function 'rust-mode)
             (lambda ()
               (setq-local font-lock-defaults '(nil t))
               (setq-local font-lock-fontify-region-function
                           (lambda (start end &optional _loudly)
                             (put-text-property start end 'face 'font-lock-warning-face)
                             (error "Native Rust grammar cannot fontify this Emacs version"))))))
    (ostadix-test-buffer "O^(rust^(fn value() {42})_rust)_O"
      (should (equal ostadix-missing-language-modes '(rust-mode)))
      (should (equal (alist-get 'rust-mode ostadix-language-mode-errors)
                     "Native Rust grammar cannot fontify this Emacs version"))
      (should (eq (ostadix-test-property "fn" 'face) 'font-lock-keyword-face))
      (should-not (ostadix-test-property "value" 'face))
      (should (eq (ostadix-test-property "42" 'face) 'font-lock-constant-face)))))

(ert-deftest ostadix-complete-active-examples-fontify-without-evaluation ()
  (let* ((case-fold-search nil)
         (root (getenv "OSTADIX_TEST_ROOT"))
         (files (append (directory-files-recursively (expand-file-name "examples" root) "\\.O\\'")
                        (directory-files-recursively (expand-file-name "apps" root) "\\.O\\'"))))
    (should (>= (length files) 54))
    (ostadix-test-without-engines
      (dolist (file files)
        (with-temp-buffer
          (insert-file-contents file)
          (ostadix-mode)
          (font-lock-ensure)
          (should-not ostadix-missing-language-modes)
          (should (equal (get-text-property (point-min) 'ostadix-language) "host")))))))
