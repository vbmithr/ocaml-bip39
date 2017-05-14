open StdLabels
open Nocrypto

type language =
  | English
  | Japanese
  | Spanish
  | Chinese_simplified
  | Chinese_traditional
  | French
  | Italian

module type LANGUAGE = sig val words : string list end

let module_of_language = function
  | English -> (module English : LANGUAGE)
  | Japanese -> (module Japanese : LANGUAGE)
  | Spanish -> (module Spanish : LANGUAGE)
  | Chinese_simplified -> (module Chinese_simplified : LANGUAGE)
  | Chinese_traditional -> (module Chinese_traditional : LANGUAGE)
  | French -> (module French : LANGUAGE)
  | Italian -> (module Italian : LANGUAGE)

let acceptable_lengths = [16 ; 20 ; 24 ; 28 ; 32]

type entropy = {
  bytes : Cstruct.t ;
  length : int ;
  digest_length : int ;
  num_words : int ;
}

let entropy_of_bytes bytes =
  match Cstruct.len bytes with
  | 16 -> { bytes ; length = 16 ; digest_length = 4 ; num_words = 12 }
  | 20 -> { bytes ; length = 20 ; digest_length = 5 ; num_words = 15 }
  | 24 -> { bytes ; length = 24 ; digest_length = 6 ; num_words = 18 }
  | 28 -> { bytes ; length = 28 ; digest_length = 7 ; num_words = 21 }
  | 32 -> { bytes ; length = 32 ; digest_length = 8 ; num_words = 24 }
  | _ -> invalid_arg "Bip39.entropy_of_bytes"

type t = {
  lang : language ;
  indices : int list ;
}

let find_index words word =
  let index = ref (-1) in
  try
    List.iteri words ~f:begin fun i w ->
      if String.compare word w = 0 then (index := i ; raise Exit)
    end ;
    raise Not_found
  with Exit -> !index

let of_words ?(lang=English) words =
  let module L = (val module_of_language lang : LANGUAGE) in
  let indices = List.map words ~f:(find_index L.words) in
  { lang ; indices }

let to_words { lang ; indices } =
  let module L = (val module_of_language lang : LANGUAGE) in
  List.map indices ~f:(List.nth L.words)

let int_of_bits bits =
  snd @@ List.fold_right bits ~init:(0, 0) ~f:begin fun b (i, res) ->
    succ i, if b then res lor (1 lsl i) else res
  end

let bits_of_char c =
  let b = Char.code c in
  if b < 0 || b > 255 then invalid_arg "Bip39.bits_of_byte" ;
  let res = ref [] in
  for i = 0 to 7 do
    res := (b land (1 lsl i) <> 0) :: !res
  done ;
  !res

let push_byte acc bits =
  List.fold_left bits ~init:acc ~f:(fun a b -> b :: a)

let bits_of_bytes bytes =
  let acc = ref [] in
  String.iter bytes ~f:begin fun c ->
    acc := push_byte !acc (bits_of_char c)
  end ;
  List.rev !acc

let list_sub l n =
  let rec inner acc n l =
    if n > 0 then match l with
      | h :: tl -> inner (h :: acc) (pred n) tl
      | _ -> invalid_arg "Bip39.list_sub"
    else List.rev acc
  in inner [] n l

let pack l pack_len =
  let rec inner (sub_acc_len, sub_acc, acc) = function
    | [] -> if sub_acc <> [] then List.rev sub_acc :: acc else acc
    | h :: tl ->
      if sub_acc_len = pack_len then
        inner (1, [h], List.rev sub_acc :: acc) tl
      else inner (succ sub_acc_len, h :: sub_acc, acc) tl
  in
  List.rev (inner (0, [], []) l)

let of_entropy ?(lang=English) entropy =
  let { bytes ; length ; digest_length ; num_words } = entropy_of_bytes entropy in
  let digest = Cstruct.get_char (Hash.SHA256.digest entropy) 0 in
  let digest = list_sub (bits_of_char digest) digest_length in
  let entropy = bits_of_bytes (Cstruct.to_string bytes) @ digest in
  let indices = List.map (pack entropy 11) ~f:int_of_bits in
  { lang ; indices }

let create ?g ?lang len =
  if not (List.mem len acceptable_lengths) then
    invalid_arg "Bip39.create: invalid length" ;
  let entropy = Rng.generate ?g len in
  of_entropy ?lang entropy

let to_seed ?(passphrase="") ({ lang ; indices } as t) =
  let words = to_words t in
  let sep = match lang with Japanese -> "\xE3\x80\x80" | _ -> " " in
  let password = Cstruct.of_string (String.concat ~sep words) in
  let salt = Cstruct.of_string ("mnemonic" ^ passphrase) in
  Pbkdf.pbkdf2 ~prf:`SHA512 ~password ~salt ~count:2048 ~dk_len:64l |>
  Cstruct.to_string
