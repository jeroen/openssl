#' Diffie-Hellman Key Agreement
#'
#' Key agreement is one-step method of creating a shared secret between two
#' peers. Both peers can independently derive the joined secret by combining
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
#' alice_key <- ec_keygen("P-521")
#' bob_key <- ec_keygen("P-521")
#'
#' # Derive public keys
#' alice_pub <- as.list(alice_key)$pubkey
#' bob_pub <- as.list(bob_key)$pubkey
#'
#'# Both peers can derive the (same) shared secret via each other's pubkey
#' ec_dh(alice_key, bob_pub)
#' ec_dh(bob_key, alice_pub)
#' }
ec_dh <- function(key = my_key(), peerkey, password = askpass){
  key <- read_key(key, password = password)
  peerkey <- read_pubkey(peerkey)
  stopifnot(inherits(key, c('ecdsa', 'x25519')))
  stopifnot(inherits(peerkey, c('ecdsa', 'x25519')))
  .Call(R_diffie_hellman, key, peerkey)
}
