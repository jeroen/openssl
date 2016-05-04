#' Diffie-Hellman Key Agreement
#'
#' Key agreement is one-step method of creating a shared secret between two
#' peers. Both peers can indendently derive the joined secret by combining
#' his or her private key with the public key from the peer.
#'
#' Currently only Elliptic Curve Diffie Hellman (ECDH) is implemented.
#'
#' @export
#' @rdname ec_dh
#' @name ec_dh
#' @useDynLib openssl R_diffie_hellman
#' @param key your own private key
#' @param peerkey the public key from your peer
#' @param password passed to \link{read_key} for reading protected private keys
#' @references \url{https://wiki.openssl.org/index.php/EVP_Key_Agreement},
#' \url{https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman}
#' @examples \dontrun{
#' # Need two EC keypairs from the same curve
#' sk1 <- ec_keygen()
#' pk1 <- as.list(sk1)$pubkey
#'
#' sk2 <- ec_keygen()
#' pk2 <- as.list(sk2)$pubkey
#'
#' # Both peers can derive the shared secret
#' alice <- ec_dh(sk1, pk2)
#' bob <- ec_dh(sk2, pk1)
#' }
ec_dh <- function(key = my_key(), peerkey, password = askpass){
  key <- read_key(key, password = password)
  peerkey <- read_pubkey(peerkey)
  stopifnot(inherits(key, "ecdsa"))
  stopifnot(inherits(peerkey, "ecdsa"))
  .Call(R_diffie_hellman, key, peerkey)
}
