# custom stopifnot() that includes a stack trace
stopifnot <- function(...){
  expr <- as.list(match.call(expand.dots = TRUE)[-1])
  values <- vapply(list(...), isTRUE, logical(1))
  if(!all(values)){
    cl <- utils::tail(sys.calls(), 2)[[1]]
    err <- sprintf("check failed: (%s)", deparse(expr[[which(!values)[1]]]))
    stop(simpleError(err, call = cl))
  }
}
