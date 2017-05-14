open Nocrypto

type language =
  | English
  | Japanese
  | Spanish
  | Chinese_simplified
  | Chinese_traditional
  | French
  | Italian

type t
(** Abstract type of a mnemonic *)

val of_words : ?lang:language -> string list -> t
(** [of_words ?lang words] is the mnemonic implied by [words] in
    [lang]. Defaults to English.

    @raises [Invalid_argument] if [List.length words] is not in {12,
    15, 18, 21, 24}. *)

val to_words : t -> string list
(** [to_words mnemonic] is the list of words corresponding to
    [mnemonic]. *)

val of_entropy : ?lang:language -> Cstruct.t -> t
(** [of_entropy ?lang bytes] is the mnemonic derived from [bytes].

    @raises [Invalid_argument] is [List.length bytes] is not in { 16,
    20, 24, 28, 32 }. *)

val create : ?g:Rng.g -> ?lang:language -> int -> t
(** [gen_mnemonic ?g length] is a BIP39 mnemonic from a generated seed
    of length [len].

    @raises [Invalid_argument] is [List.length bytes] is not in { 16,
    20, 24, 28, 32 }. *)

val to_seed :
  ?passphrase:string -> t -> string
(** [seed_of_mnemonic ?passphrase mnemonic] is a 64 bytes long string
    derived from a BIP39 mnemonic [mnemonic], using the optional
    passphrase [passphrase] if provided. *)

