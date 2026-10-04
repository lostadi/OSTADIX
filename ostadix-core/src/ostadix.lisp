;; src/ostadix.lisp
(defpackage :ostadix
  (:use :cl))
(in-package :ostadix)

;; 1. The Dynamic Nix Environment Builder
(defun with-nix (packages)
  (let* ((pkg-string (format nil "~{~A ~}" packages))
         (cmd (format nil "nix-shell -p ~A --run 'ostadix-injector $SHELL'" pkg-string)))
    (format t "~%[~C[36mOSTADIX~C[0m] Provisioning pure Nix environment with: ~A~%"
            #\Esc #\Esc pkg-string)
    (uiop:run-program cmd :output :interactive :input :interactive)))

;; 2. Nixpkgs Search directly from Lisp
(defun ostadix-search (query)
  (format t "[~C[36mOSTADIX~C[0m] Searching Nixpkgs database for '~A'...~%"
          #\Esc #\Esc query)
  (uiop:run-program (format nil "nix search nixpkgs ~A" query)
                    :output :interactive))

;; 3. Hardware-Native Compilation Engine
;;    Usage: (ostadix-build-native :ffmpeg)
(defun ostadix-build-native (pkg-name)
  (let* ((pkg (string-downcase (symbol-name pkg-name)))
         (nix-expr
           (format nil
             "with import <nixpkgs> {}; ~A.overrideAttrs (old: { NIX_CFLAGS_COMPILE = \"-march=native -O3 \" + (old.NIX_CFLAGS_COMPILE or \"\"); })"
             pkg)))
    (format t "[~C[36mOSTADIX~C[0m] Forcing hardware-native compilation for ~A...~%"
            #\Esc #\Esc pkg)
    (uiop:run-program
      (format nil "nix-build --impure -E '~A'" nix-expr)
      :output :interactive)))

;; 4. Live Kernel Parameter Patching
;;    Usage: (kernel-set "vm.swappiness" 1)
(defun kernel-set (param value)
  (format t "[~C[36mOSTADIX~C[0m] Patching live kernel: ~A -> ~A~%"
          #\Esc #\Esc param value)
  (uiop:run-program
    (format nil "sudo sysctl -w ~A=~A" param value)
    :output :interactive))

;; 5. Kernel Module Injector
;;    Usage: (kernel-load-module :bpf)
(defun kernel-load-module (mod-name)
  (let ((mod (string-downcase (symbol-name mod-name))))
    (format t "[~C[36mOSTADIX~C[0m] Injecting module into kernel: ~A~%" mod)
    (uiop:run-program (format nil "sudo modprobe ~A" mod)
                      :output :interactive)))
