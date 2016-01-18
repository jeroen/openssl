#' Password Prompt Utility
#'
#' Function to prompt the user for a password to read a protected private key.
#' Frontends can provide a custom password entry widget by setting the \code{askpass}
#' option. If no such option is specified we default to \code{\link{readline}}.
#'
#' @export
#' @param prompt the string printed when prompting the user for input.
askpass <- function(prompt = "Please enter your password: "){
  FUN <- getOption("askpass", readline)
  FUN(prompt)
}
