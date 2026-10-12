;;; ostadix-mode.el --- Nested Ostadix polyglot highlighting -*- lexical-binding: t; -*-
;; Generated asset: edit this template and run ../editors/generate.py write.
;; O structure is parsed before foreign fontification, including markers inside
;; foreign comments/strings. The runtime remains authoritative for validation.

(require 'cl-lib)
(require 'font-lock)
(defvar native-comp-jit-compilation)
(defvar native-comp-deferred-compilation)
@LANGUAGE_METADATA@

(defconst ostadix--mode-libraries
  '((rust-mode . "rust-mode") (racket-mode . "racket-mode")
    (nix-mode . "nix-mode") (markdown-mode . "markdown-mode")
    (haskell-mode . "haskell-mode") (tuareg-mode . "tuareg")
    (wat-mode . "wat-mode") (wolfram-mode . "wolfram-mode")))

;; Append offline sources so installed packages and existing autoloads keep
;; precedence.  Loading this file neither installs packages nor starts engines.
(let ((vendor (expand-file-name "vendor/"
                                (file-name-directory (or load-file-name buffer-file-name)))))
  (dolist (package '("compat" "cond-let" "llama" "magit-section" "transient"
                     "reformatter" "rust-mode" "racket-mode" "nix-mode"
                     "markdown-mode" "haskell-mode" "tuareg" "wat-mode" "wolfram-mode"))
    (let ((directory (expand-file-name package vendor)))
      (when (file-directory-p directory)
        (add-to-list 'load-path directory t)))))
(dolist (entry ostadix--mode-libraries)
  (unless (fboundp (car entry))
    (when (locate-library (cdr entry))
      (autoload (car entry) (cdr entry) nil t))))

(defvar-local ostadix-missing-language-modes nil
  "Foreign modes unavailable or failing in this buffer; lexical fallbacks are used.")
(defvar-local ostadix-language-mode-errors nil
  "Alist of failed foreign modes and their exact error messages in this buffer.
An unavailable mode has an explicit absence message instead of a signaled error.")
(defvar-local ostadix--fontified-tick nil)
(defconst ostadix--identifier "[A-Za-z_][A-Za-z0-9_]*")
(defconst ostadix--environment "\\[\\(?:[0-9]+\\|\\*\\)\\]")
(defconst ostadix--attributes
  (concat "{[ \t]*" ostadix--identifier "\\(?:=[!-+--<>-z|~]+\\)?"
          "\\(?:[ \t]*,[ \t]*" ostadix--identifier "\\(?:=[!-+--<>-z|~]+\\)?\\)*[ \t]*}"))
(defconst ostadix--header
  (concat (regexp-opt (apply #'append (mapcar #'cadr ostadix--languages)))
          "\\(?:" ostadix--environment "\\)?\\(?:" ostadix--attributes "\\)?"))
(defconst ostadix--opener (concat ostadix--header "\\^("))
(defconst ostadix--closer (concat ")_" ostadix--header))
(defconst ostadix--candidate
  (concat "\\\\\\|\\$" ostadix--identifier "\\|#\\|" ostadix--opener "\\|" ostadix--closer))

(defun ostadix--language (header)
  (let ((tag (car (split-string header "[\\[{]"))))
    (cl-find-if (lambda (language) (member tag (cadr language))) ostadix--languages)))

(defun ostadix--complete-closer-p (header end)
  "Apply the runtime's exact closer suffix rule to HEADER ending at END."
  (or (string-match-p "{" header)
      (if (string-match-p "\\[" header)
          (not (eq (char-after end) ?{))
        (not (and (char-after end)
                  (string-match-p "[A-Za-z0-9_\\[{]" (char-to-string (char-after end))))))))

(defun ostadix--scan ()
  "Return (NODES MARKERS) using an iterative stack with no nesting ceiling."
  (save-excursion
    (goto-char (point-min))
    (let* ((root (list :language (car ostadix--languages) :body-start (point-min)
                       :body-end (point-max) :end (point-max) :children nil))
           (stack (list root)) (nodes (list root)) markers)
      (while (re-search-forward ostadix--candidate nil t)
        (let* ((start (match-beginning 0)) (end (match-end 0))
               (token (match-string-no-properties 0)) (parent (car stack))
               (host (equal (car (plist-get parent :language)) "host")))
          (cond
           ((equal token "\\")
            (when (or (looking-at ostadix--opener) (looking-at ostadix--closer)
                      (looking-at "\\$"))
              (let ((escape-end (match-end 0)))
                (push (list start escape-end 'font-lock-escape-face) markers)
                (goto-char escape-end))))
           ((equal token "#")
            (when host
              (end-of-line)
              (push (list start (point) 'font-lock-comment-face) markers)))
           ((string-prefix-p "$" token)
            (push (list start end 'font-lock-variable-name-face) markers))
           ((string-prefix-p ")_" token)
            (let ((header (substring token 2)))
              (when (and (cdr stack) (equal header (plist-get parent :header))
                         (ostadix--complete-closer-p header end))
                (setf (plist-get parent :body-end) start
                      (plist-get parent :end) end)
                (push (list start end 'font-lock-preprocessor-face) markers)
                (pop stack))))
           (t
            (let* ((header (substring token 0 -2))
                   (node (list :language (ostadix--language header) :header header
                               :start start :body-start end :body-end (point-max)
                               :end (point-max) :children nil)))
              (push node (plist-get parent :children))
              (push node nodes)
              (push node stack)
              (push (list start end 'font-lock-preprocessor-face) markers))))))
      (list (nreverse nodes) markers))))

(defun ostadix--fallback-fontify (language)
  "Apply small, language-specific lexical aids when LANGUAGE has no mode."
  (let ((words (split-string (nth 3 language) " " t))
        (case-fold-search (equal (car language) "sql")))
    (when words
      (goto-char (point-min))
      (while (re-search-forward (regexp-opt words 'symbols) nil t)
        (put-text-property (match-beginning 0) (match-end 0) 'face 'font-lock-keyword-face)))
    (unless (member (car language) '("text" "html" "markdown"))
      (goto-char (point-min))
      (while (re-search-forward "\\_<[0-9]+\\(?:\\.[0-9]+\\)?\\_>" nil t)
        (put-text-property (match-beginning 0) (match-end 0) 'face 'font-lock-constant-face))
      (goto-char (point-min))
      (while (re-search-forward "\"\\(?:\\\\.\\|[^\"\\\\]\\)*\"\\|'\\(?:\\\\.\\|[^'\\\\]\\)*'" nil t)
        (put-text-property (match-beginning 0) (match-end 0) 'face 'font-lock-string-face)))))

(defun ostadix--record-mode-error (target mode message)
  "Record MODE's failure MESSAGE in the document buffer TARGET."
  (with-current-buffer target
    (cl-pushnew mode ostadix-missing-language-modes)
    (setf (alist-get mode ostadix-language-mode-errors) message)))

(defun ostadix--fontify-node (node target)
  "Fontify NODE's body with child blocks masked, then transfer its faces to TARGET."
  (let* ((start (plist-get node :body-start)) (end (plist-get node :body-end))
         (language (plist-get node :language)) (mode (nth 2 language))
         (source (with-current-buffer target (buffer-substring-no-properties start end))))
    (when (< start end)
      (with-current-buffer target
        (remove-text-properties start end '(face nil font-lock-face nil))
        (put-text-property start end 'ostadix-language (car language)))
      (with-temp-buffer
        (insert source)
        ;; Preserve character offsets and line breaks while hiding a child's
        ;; grammar from its parent. This retains the parent's string/comment state.
        (dolist (child (plist-get node :children))
          (let ((from (1+ (- (plist-get child :start) start)))
                (to (1+ (- (plist-get child :end) start))))
            (let ((masked (replace-regexp-in-string "[^\n\r]" " "
                                                    (buffer-substring-no-properties from to))))
              (delete-region from to)
              (goto-char from)
              (insert masked))))
        (let ((masked-source (buffer-substring-no-properties (point-min) (point-max))))
          (if (and (not (eq mode 'ostadix-mode)) (fboundp mode))
              (condition-case failure
                  (let ((inhibit-message t) (message-log-max nil)
                        ;; Source grammars need no compiler subprocess.  Do not turn
                        ;; loading a bundled mode into deferred native compilation.
                        (native-comp-jit-compilation nil)
                        (native-comp-deferred-compilation nil))
                    (delay-mode-hooks (funcall mode))
                    (font-lock-ensure (point-min) (point-max)))
                (error
                 (ostadix--record-mode-error target mode (error-message-string failure))
                 ;; An incompatible mode can leave partial faces, hooks, narrowed
                 ;; text, or even changed content.  Restore the original masked
                 ;; body before applying the fallback so offsets remain exact.
                 (let ((inhibit-read-only t) (inhibit-modification-hooks t)
                       (buffer-undo-list t))
                   (widen)
                   (delay-mode-hooks (fundamental-mode))
                   (erase-buffer)
                   (insert masked-source))
                 (ostadix--fallback-fontify language)))
            (unless (eq mode 'ostadix-mode)
              (ostadix--record-mode-error
               target mode (format "Major mode `%s' is unavailable" mode)))
            (ostadix--fallback-fontify language)))
        (let ((position (point-min)))
          (while (< position (point-max))
            (let* ((next (next-single-property-change position 'face nil (point-max)))
                   (face (get-text-property position 'face)))
              (when face
                (with-current-buffer target
                  (put-text-property (+ start (1- position)) (+ start (1- next)) 'face face)))
              (setq position next))))))))

(defun ostadix--unfontify (start end)
  (setq ostadix--fontified-tick nil)
  (remove-text-properties start end '(face nil font-lock-face nil ostadix-language nil)))

(defun ostadix--fontify (_start _end &optional _loudly)
  "Refresh complete structural state when an edit invalidates highlighting."
  (unless (equal ostadix--fontified-tick (buffer-chars-modified-tick))
    (save-restriction
      (widen)
      (with-silent-modifications
        (ostadix--unfontify (point-min) (point-max))
        (setq ostadix-missing-language-modes nil
              ostadix-language-mode-errors nil)
        (pcase-let ((`(,nodes ,markers) (ostadix--scan)))
          (dolist (node nodes) (ostadix--fontify-node node (current-buffer)))
          (dolist (marker markers)
            (put-text-property (nth 0 marker) (nth 1 marker) 'face (nth 2 marker))))
        (setq ostadix--fontified-tick (buffer-chars-modified-tick))))))

;;;###autoload
(define-derived-mode ostadix-mode prog-mode "Ostadix"
  "Edit hosted Ostadix source with nested foreign-language highlighting.
Bundled native foreign modes supply their complete lexical grammars offline.
Installed foreign modes take precedence over bundled sources.
`ostadix-missing-language-modes' lists the modes using lexical fallbacks.
`ostadix-language-mode-errors' records their exact fontification errors.
This mode does not execute code, install packages, or validate programs."
  (setq-local comment-start "# ")
  (setq-local font-lock-defaults '(nil t))
  (setq-local font-lock-fontify-region-function #'ostadix--fontify)
  (setq-local font-lock-unfontify-region-function #'ostadix--unfontify))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.\\(?:O\\|olang\\)\\'" . ostadix-mode))
(provide 'ostadix-mode)
;;; ostadix-mode.el ends here
