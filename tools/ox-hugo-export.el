;;; ox-hugo-export.el --- Export every Org file of the blog with ox-hugo -*- lexical-binding: t; -*-
;;
;; Used by `make export'. Commit its output (content/, static/ox-hugo/):
;; the GitHub Actions workflow only runs Hugo.
;;
;;   emacs --batch -l tools/ox-hugo-export.el
;;
;; - Uses the ox-hugo already installed in ~/.emacs.d when there is one,
;;   otherwise installs it from MELPA (CI, or when KRAKZ_ELPA_DIR is set).
;; - Exports every subtree with an EXPORT_FILE_NAME of every content-org/*.org.
;; - Org Babel blocks are NOT evaluated: commit the #+RESULTS you want shown.

(require 'package)

;; Make sure the export behaves the same everywhere (emoji in titles…)
(set-language-environment "UTF-8")
(prefer-coding-system 'utf-8)
(setq coding-system-for-read 'utf-8
      coding-system-for-write 'utf-8)

(let ((dir (getenv "KRAKZ_ELPA_DIR")))
  (when (and dir (not (string-empty-p dir)))
    (setq package-user-dir (expand-file-name dir))))

(add-to-list 'package-archives '("melpa" . "https://melpa.org/packages/") t)
(package-initialize)

(unless (require 'ox-hugo nil t)
  (message "[export] ox-hugo not found, installing it from MELPA into %s" package-user-dir)
  (package-refresh-contents)
  (package-install 'ox-hugo)
  (require 'ox-hugo))

(setq org-export-use-babel nil            ; never run code during export
      org-confirm-babel-evaluate nil
      make-backup-files nil)

(let* ((root (file-name-directory
              (directory-file-name
               (file-name-directory (or load-file-name buffer-file-name)))))
       (org-dir (expand-file-name "content-org" root))
       (failed nil))
  ;; ox-hugo refuses to copy images when static/ does not exist
  (make-directory (expand-file-name "static" root) t)
  ;; ox-hugo resolves relative image links (images/<article>/…) and
  ;; HUGO_BASE_DIR (../) against the process directory: run from content-org/.
  (cd org-dir)
  (dolist (file (directory-files org-dir t "\\.org\\'"))
    (message "[export] %s" (file-relative-name file root))
    (condition-case err
        (with-current-buffer (find-file-noselect file)
          (org-hugo-export-wim-to-md :all-subtrees)
          (kill-buffer))
      (error (setq failed t)
             (message "[export] FAILED %s: %s" file (error-message-string err)))))
  (when failed (kill-emacs 1)))

;;; ox-hugo-export.el ends here
