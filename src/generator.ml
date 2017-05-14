open Base
open Stdio

let pp_print_quoted_string ppf str =
  let open Caml.Format in
  fprintf ppf "\"%s\"" str

let pp_print_quoted_string_list ppf strs =
  let open Caml.Format in
  pp_print_list ~pp_sep:(fun ppf () -> pp_print_string ppf ";")
    pp_print_quoted_string ppf strs

let main () =
  let ml_files = String.split ~on:' ' Caml.Sys.argv.(1) in
  let txt_files = List.map ml_files ~f:begin fun lang ->
      "../gen/" ^ (Caml.Filename.remove_extension lang) ^ ".txt"
    end in
  List.iter2_exn ml_files txt_files ~f:begin fun ml_file txt_file ->
    let words = In_channel.read_lines txt_file in
    Out_channel.with_file
      ~binary:false ~append:false ~fail_if_exists:false ml_file ~f:begin fun oc ->
      let ppf = Caml.Format.formatter_of_out_channel oc in
      Caml.Format.fprintf ppf "let words = [%a]@." pp_print_quoted_string_list words
    end
  end

let () = main ()
