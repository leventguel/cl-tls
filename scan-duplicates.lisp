(defun scan-utils-for-duplicates (directory)
  (ensure-directories-exist directory)
  "Scan all .lisp files in DIRECTORY for duplicate defun names."
  (let ((function-table (make-hash-table :test 'equal)))
    (labels ((collect-defuns (file)
               (with-open-file (stream file)
                 (loop for line = (read-line stream nil)
                       while line
                       do (when (search "(defun " line)
                            (let ((start (search "(defun " line)))
                              (when start
                                (let* ((rest (subseq line (+ start 7)))
                                       (name (string-trim '(#\Space #\Tab #\Newline #\() rest)))
                                  (setf name (subseq name 0 (position #\Space name)))
                                  (push file (gethash name function-table)))))))))
             (scan-directory (dir)
               (loop for file in (directory (merge-pathnames "*.lisp" dir))
                     do (collect-defuns file))))
      (scan-directory directory)
      ;; Print duplicates
      (maphash (lambda (name files)
                 (when (> (length files) 1)
                   (format t "~%Duplicate function ~A found in:~%~{~A~%~}" name files)))
               function-table))))
