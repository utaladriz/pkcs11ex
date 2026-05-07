defmodule Pkcs11ex.Conformance.PDFPdfsigTest do
  @moduledoc """
  Standards-conformance check for `SignCore.PDF.sign/2` against the
  Poppler `pdfsig` CLI — the canonical third-party PAdES verifier
  shipped on every major Linux distro and Homebrew.

  Confirms our hand-rolled CMS + incremental-update emitter produces
  bytes a real verifier accepts. Excluded by default; opt in via:

      mix test --include conformance

  Requires:

    * SoftHSM2 (the existing :softhsm fixture).
    * `pdfsig` from Poppler — `brew install poppler` on macOS,
      `apt-get install poppler-utils` on Debian.

  Notes:

    * pdfsig reports two independent statuses per signature:
      "Signature Validation" (the math) and "Certificate Validation"
      (chain trust). We assert the former; the latter will always
      report "Certificate is Trusted." or "Certificate issuer isn't
      trusted." depending on whether the leaf's issuer is in the
      system trust store. The test cert is software-self-signed so
      cert validation is expected to fail; the math check is the
      one that proves CMS / ByteRange correctness.
    * pdfsig version skew across distros means we accept several
      "math passed" phrasings.
  """

  use ExUnit.Case, async: false

  @moduletag :conformance
  @moduletag :softhsm

  # Tool presence is determined at compile time — if pdfsig isn't on
  # PATH the actual test bodies don't compile, replaced with a single
  # "skipped" placeholder. ExUnit's include/exclude semantics can't
  # express "only if tool present" cleanly when the user passes
  # `--include conformance`, so we lean on the compiler.
  if pdfsig = System.find_executable("pdfsig") do
    @pdfsig pdfsig

    alias Pkcs11ex.Native
    alias Pkcs11ex.PDF

    setup_all do
      softhsm2_util = System.find_executable("softhsm2-util")
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)
      {:ok, bootstrap(softhsm2_util)}
    end

    test "PDF.sign/2 (B-B) output verifies under pdfsig", ctx do
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          placeholder_size: 4096
        )

      pdf_path = write_temp_pdf(signed_pdf, "conformance-bb")
      {output, status} = System.cmd(@pdfsig, [pdf_path], stderr_to_stdout: true)

      assert pdfsig_signature_valid?(output),
             "pdfsig did NOT confirm signature math.\nExit: #{status}\nOutput:\n#{output}"
    end

    @tag :tsa
    test "PDF.sign/2 (B-T) output verifies under pdfsig and embeds a TST", ctx do
      tsa_url = System.get_env("PKCS11EX_TSA_URL") || "http://timestamp.digicert.com"
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          tsa_url: tsa_url,
          tsa_timeout: 15_000,
          placeholder_size: 16_384
        )

      pdf_path = write_temp_pdf(signed_pdf, "conformance-bt")
      {output, status} = System.cmd(@pdfsig, [pdf_path], stderr_to_stdout: true)

      assert pdfsig_signature_valid?(output),
             "pdfsig did NOT confirm signature math on B-T PDF.\nExit: #{status}\nOutput:\n#{output}"
    end

    # ---------- helpers ----------

    defp pdfsig_signature_valid?(output) do
      output =~ "Signature Validation: Signature is Valid." or
        output =~ "Signature is valid" or
        output =~ "Signature Validity: Signature is Valid"
    end

    defp write_temp_pdf(bytes, prefix) do
      path = Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}.pdf")
      File.write!(path, bytes)
      on_exit(fn -> File.rm(path) end)
      path
    end

    defp bootstrap(softhsm2_util) do
      suffix = System.unique_integer([:positive])
      token_label = "pkcs11ex-conf-pdf-#{suffix}"
      key_label = "pkcs11ex-conf-pdf-key-#{suffix}"
      user_pin = "1234"
      so_pin = "1234"

      slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)
      on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

      pkcs11_module = Pkcs11ex.Test.SoftHSM.module()
      {:ok, true} = Native.generate_rsa_keypair(pkcs11_module, slot_id, user_pin, key_label, 2048)

      {:ok, {modulus_list, exponent_list}} =
        case Native.export_rsa_public_key(pkcs11_module, slot_id, key_label) do
          {:ok, pair} -> {:ok, pair}
          {modulus, exponent} -> {:ok, {modulus, exponent}}
        end

      modulus_bin = IO.iodata_to_binary(modulus_list)
      exponent_bin = IO.iodata_to_binary(exponent_list)
      softhsm_pubkey = build_rsa_public_key(modulus_bin, exponent_bin)
      leaf_der = build_wrapper_cert(softhsm_pubkey)

      %{
        pkcs11_module: pkcs11_module,
        slot_id: slot_id,
        pin: user_pin,
        key_label: key_label,
        leaf_der: leaf_der
      }
    end

    defp build_rsa_public_key(modulus_bin, exponent_bin) do
      modulus = :binary.decode_unsigned(modulus_bin, :big)
      exponent = :binary.decode_unsigned(exponent_bin, :big)
      {:RSAPublicKey, modulus, exponent}
    end

    defp build_wrapper_cert(rsa_pubkey) do
      issuer_key = X509.PrivateKey.new_rsa(2048)
      issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-conformance-issuer")

      leaf_cert =
        X509.Certificate.new(
          rsa_pubkey,
          "/CN=pkcs11ex-conformance-leaf",
          issuer_cert,
          issuer_key
        )

      X509.Certificate.to_der(leaf_cert)
    end

    defp build_minimal_pdf do
      objects = [
        {1, "<< /Type /Catalog /Pages 2 0 R >>"},
        {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
        {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
      ]

      header = "%PDF-1.7\n"

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

      body <>
        "xref\n0 #{size}\n" <>
        entries <>
        "trailer\n<< /Size #{size} /Root 1 0 R >>\n" <>
        "startxref\n#{startxref_offset}\n%%EOF\n"
    end
  else
    test "skipped — pdfsig not on PATH (install: brew install poppler)" do
      IO.puts(
        "[skip] Pkcs11ex.Conformance.PDFPdfsigTest — pdfsig not on PATH. " <>
          "Install with `brew install poppler` (macOS) or " <>
          "`apt-get install poppler-utils` (Debian)."
      )
    end
  end
end
