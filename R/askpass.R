#' Password Prompt Utility
#'
#' Function to prompt the user for a password to read a protected private key.
#' Frontends can provide a custom password entry widget by setting the \code{askpass}
#' option. If no such option is specified we default to \code{\link{readline}}.
#'
#' @export
#' @param prompt the string printed when prompting the user for input.
askpass <- function(prompt = "Please enter your password: "){
  if(!interactive())
    return(NULL)
  FUN <- getOption("askpass", readline_silent)
  FUN(prompt)
}

readline_silent <- function(prompt){
  if(is_unix() && isatty(stdin())){
    if(system('stty -echo') == 0){
      on.exit(system('stty echo'))
    }
  }
  cat(prompt, "\n")
  out <- base::readline("\U0001f511 ")
  cat(" OK\n")
  out
}

readline_bash <- function(prompt){
  args <- sprintf('-s -p "%s" password && echo $password', prompt)
  on.exit({system('stty echo'); cat("\n")})
  system2('read', args, stdout = TRUE)
}

is_unix <- function(){
  .Platform$OS.type == "unix"
}

is_macos <- function(){
  identical(tolower(Sys.info()[['sysname']]), "darwin")
}

