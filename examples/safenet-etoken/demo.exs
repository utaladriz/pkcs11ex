# pkcs11ex — SafeNet eToken demo
#
# Signs a one-page PDF with the eToken's hardware-resident RSA-2048
# key and writes the result to `signed_demo.pdf` in the current
# working directory.
#
# Usage (from the project root):
#
#     PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \
#       MIX_ENV=test mix run examples/safenet-etoken/demo.exs
#
# `MIX_ENV=test` is required because the demo uses the `:x509` Hex
# package (test-only dep) to build a wrapper cert around the
# eToken's public key. `PKCS11EX_SAFENET_KEY_LABEL` defaults to ""
# which auto-matches the only keypair on the token (typical for
# self-generated SafeNet keys with no `CKA_LABEL` set).
#
# After it writes the PDF, the demo:
#
#   * self-verifies via `SignCore.PDF.verify/2` (Allow policy)
#   * runs `pdfsig` if available — third-party verifier confirmation

driver =
  System.get_env("PKCS11EX_SAFENET_LIB") ||
    "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib"

pin =
  System.get_env("PKCS11EX_SAFENET_PIN") ||
    raise("PKCS11EX_SAFENET_PIN env var required — see comments at top of script")

key_label = System.get_env("PKCS11EX_SAFENET_KEY_LABEL") || ""

{:ok, mod} = Pkcs11ex.Native.module_load(driver)
{:ok, slot_info} = Pkcs11ex.Native.list_slots(mod)
slot = Enum.find(slot_info, & &1.token_present) || raise("no eToken plugged in")

slot_ref = :etoken_demo

slot_config = [
  type: :token,
  driver: driver,
  slot_match: {:slot_id, slot.slot_id},
  pin_callback: nil,
  keys: [signing: [label: key_label]],
  lazy: true,
  reauthentication: :prompt
]

# Slot.Registry is already running (started by Pkcs11ex.Application).
{:ok, _} =
  Pkcs11ex.Slot.Server.start_link(
    slot_ref: slot_ref,
    slot_config: slot_config,
    module: mod
  )

Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

# Build a wrapper cert wrapping the eToken's actual public key so
# `x5c` carries the right SPKI for verifiers. In production you'd
# use a CA-issued cert that already wraps the same public key.
{:ok, {modulus_list, exp_list}} =
  Pkcs11ex.Native.export_rsa_public_key(mod, slot.slot_id, key_label)

modulus = modulus_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
exp = exp_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
rsa_pubkey = {:RSAPublicKey, modulus, exp}

issuer_key = X509.PrivateKey.new_rsa(2048)
issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-demo-issuer")
leaf_cert = X509.Certificate.new(rsa_pubkey, "/CN=pkcs11ex-demo-leaf", issuer_cert, issuer_key)
leaf_der = X509.Certificate.to_der(leaf_cert)

# Build a PDF with visible text so it's interesting to open.
content_stream =
  "BT\n/F1 18 Tf\n72 720 Td\n(Signed by SafeNet eToken) Tj\n" <>
    "0 -30 Td\n/F1 12 Tf\n(pkcs11ex demo - " <>
    DateTime.to_iso8601(DateTime.utc_now()) <> ") Tj\nET"

content_obj =
  "<< /Length #{byte_size(content_stream)} >>\nstream\n#{content_stream}\nendstream"

objects = [
  {1, "<< /Type /Catalog /Pages 2 0 R >>"},
  {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
  {3,
   "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " <>
     "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"},
  {4, content_obj},
  {5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
]

header = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"

{body, offsets} =
  Enum.reduce(objects, {header, %{}}, fn {num, content}, {acc, offs} ->
    offset = byte_size(acc)
    obj_bytes = "#{num} 0 obj\n#{content}\nendobj\n"
    {acc <> obj_bytes, Map.put(offs, num, offset)}
  end)

startxref_offset = byte_size(body)
size = Enum.max(Map.keys(offsets)) + 1

entries =
  Enum.map_join(0..(size - 1), "", fn n ->
    case Map.get(offsets, n) do
      nil ->
        if n == 0, do: "0000000000 65535 f \n", else: "0000000000 00000 f \n"

      offset ->
        offset_str = String.pad_leading(Integer.to_string(offset), 10, "0")
        "#{offset_str} 00000 n \n"
    end
  end)

base_pdf =
  body <>
    "xref\n0 #{size}\n" <>
    entries <>
    "trailer\n<< /Size #{size} /Root 1 0 R >>\n" <>
    "startxref\n#{startxref_offset}\n%%EOF\n"

{:ok, signed_pdf} =
  SignCore.PDF.sign(base_pdf,
    signer: {slot_ref, :signing},
    alg: :PS256,
    x5c: leaf_der,
    pin: pin,
    placeholder_size: 4096,
    reason: "pkcs11ex eToken demo",
    location: "Santiago, CL"
  )

out = Path.expand("signed_demo.pdf")
File.write!(out, signed_pdf)
IO.puts("--- wrote #{byte_size(signed_pdf)}-byte PDF to #{out}")

case SignCore.PDF.verify(signed_pdf, trust_policy: SignCore.Policy.Allow) do
  {:ok, sid} -> IO.puts("--- SignCore.PDF.verify: OK (subject_id=#{inspect(sid)})")
  err -> IO.puts("--- SignCore.PDF.verify: #{inspect(err)}")
end

case System.find_executable("pdfsig") do
  nil ->
    IO.puts("--- (pdfsig not on PATH; skip third-party check)")

  bin ->
    {output, _status} = System.cmd(bin, [out], stderr_to_stdout: true)

    if output =~ "Signature is Valid" do
      IO.puts("--- pdfsig: Signature is Valid")
    else
      IO.puts("--- pdfsig output (full):\n#{output}")
    end
end
