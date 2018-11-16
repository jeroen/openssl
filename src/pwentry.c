#include <R.h>
#include <Rinternals.h>

#ifdef WIN32
#include <windows.h>
#include <wincred.h>
#else
#include <unistd.h>
#endif

static SEXP safe_char(const char *x){
  if(x == NULL)
    return NA_STRING;
  return Rf_mkCharCE(x, CE_UTF8);
}

SEXP pw_entry_dialog(SEXP prompt, SEXP username){
#ifndef _WIN32 // UNIX version:
  const char *text = CHAR(STRING_ELT(prompt, 0));
  return Rf_ScalarString(safe_char(getpass(text)));
#else //WINDOWS version:
  CREDUI_INFO cui;
  TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH+1];
  TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH+1];
  BOOL fSave;
  DWORD dwErr;

  REprintf("Opening credential dialog (Window may appear behind this one)\n");
  R_FlushConsole();

  int user_fixed = Rf_length(username);
  cui.cbSize = sizeof(CREDUI_INFO);
  cui.hwndParent = GetActiveWindow();
  cui.pszMessageText = TEXT(CHAR(STRING_ELT(prompt, 0)));
  cui.pszCaptionText = TEXT("Password Entry");
  cui.hbmBanner = NULL;
  fSave = FALSE;
  SecureZeroMemory(pszName, sizeof(pszName));
  SecureZeroMemory(pszPwd, sizeof(pszPwd));
  if(user_fixed){
    strcpy(pszName, CHAR(STRING_ELT(username, 0)));
  }
  dwErr = CredUIPromptForCredentials(
    &cui,                         // CREDUI_INFO structure
    TEXT("TheServer"),            // Target for credentials
    NULL,                         // Reserved
    0,                            // Reason
    pszName,                      // User name
    CREDUI_MAX_USERNAME_LENGTH, // Max number of char for user name
    pszPwd,                       // Password
    CREDUI_MAX_PASSWORD_LENGTH+1, // Max number of char for password
    &fSave,                       // State of save check box
    CREDUI_FLAGS_GENERIC_CREDENTIALS |  // flags
    CREDUI_FLAGS_KEEP_USERNAME * user_fixed |
    CREDUI_FLAGS_PASSWORD_ONLY_OK * user_fixed |
    CREDUI_FLAGS_ALWAYS_SHOW_UI |
    CREDUI_FLAGS_DO_NOT_PERSIST);

  if(!dwErr) {
    SEXP out = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(out, 0, safe_char(pszPwd));
    SET_STRING_ELT(out, 1, safe_char(pszName));
    UNPROTECT(1);
    return out;
  }
  return R_NilValue;
#endif
}

