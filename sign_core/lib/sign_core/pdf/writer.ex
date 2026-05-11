defmodule SignCore.PDF.Writer do
  @moduledoc """
  Hand-rolled PAdES B-B incremental-update emitter.

  The writer takes a base PDF and produces an incremental update with a
  PKCS#7-detached `/Sig` dictionary whose `/Contents` is a fixed-size hex
  placeholder. The caller then:

    1. signs the bytes the writer reports as `:signed_input` via
       `Pkcs11ex.sign_bytes/2` (or any equivalent CMS pipeline);
    2. calls `inject_signature/2` to splice the resulting CMS DER into
       the placeholder.

  The two-phase shape is mandatory: PAdES `/ByteRange` covers everything
  except the hex digits, so the bytes-to-be-signed cannot be known until
  the placeholder's exact byte offset is fixed.

  ### What the writer emits

  Three new objects are appended:

    * the existing catalog re-emitted with `/AcroForm` extended (or
      added) so the new `/Sig` field is reachable from `/Root`;
    * a signature field annotation (`/FT /Sig`, `/Subtype /Widget`,
      invisible 0×0 rect) referencing the `/Sig` dict via `/V`;
    * the `/Sig` dict itself: `/Filter /Adobe.PPKLite`,
      `/SubFilter /ETSI.CAdES.detached` (ETSI EN 319 142-1 §6.2.1),
      fixed-width `/ByteRange` and `/Contents` placeholders, plus
      optional `/M`, `/Reason`, `/Location`.

  Followed by a fresh xref subsection (one entry per new object number,
  plus one for the re-emitted catalog), trailer with `/Prev` pointing
  at the original `startxref`, and the new `startxref` + `%%EOF`.

  ### v1 limitations

    * Refuses to merge with an existing `/AcroForm`. Re-signing a PDF
      that already has form fields needs full PDF object grammar; out
      of scope for v1. Returns
      `{:error, {:writer, :existing_acroform_unsupported_in_v1}}`.
    * Refuses to operate on PDFs whose `/Root` catalog uses a cross-
      reference stream (Reader returns `:xref_stream_unsupported`).
    * The `/Sig` field is invisible — no widget rectangle, no rendering
      hints. Visible signature appearance streams are a Phase 4b.x
      feature.
  """

  alias SignCore.PDF.Reader

  @default_placeholder_size 8_192

  defstruct [
    :pdf,
    :signed_input,
    :contents_offset,
    :contents_length,
    :byte_range,
    :placeholder_size
  ]

  @typedoc """
  Output of `prepare/2`. The caller hashes `:signed_input`, builds a
  CMS over that hash, and feeds the CMS DER to `inject_signature/2`.
  """
  @type t :: %__MODULE__{
          pdf: binary(),
          signed_input: binary(),
          contents_offset: non_neg_integer(),
          contents_length: non_neg_integer(),
          byte_range: [non_neg_integer()],
          placeholder_size: pos_integer()
        }

  @typedoc """
  Per-call options:

    * `:placeholder_size` — bytes the CMS DER will occupy. The hex
      placeholder in the PDF is exactly twice this many ASCII chars.
      Default `#{@default_placeholder_size}`. Real-world PAdES B-B
      signatures with a single end-entity cert and no timestamp run
      ~6 KiB; raise this when embedding LTV material.
    * `:signing_time` — `DateTime.t()` for the `/M` entry in the Sig
      dict. Default `DateTime.utc_now/0`. Note: PAdES verifiers
      generally trust the CMS `signing-time` attribute, not `/M`.
    * `:reason`, `:location`, `:contact_info` — optional `/Reason`,
      `/Location`, `/ContactInfo` entries in the Sig dict.
  """
  @type prepare_opts :: [
          placeholder_size: pos_integer(),
          signing_time: DateTime.t(),
          reason: String.t(),
          location: String.t(),
          contact_info: String.t()
        ]

  @doc """
  Builds the incremental-update bytes and returns the structure
  describing what to sign.
  """
  @spec prepare(binary(), prepare_opts()) :: {:ok, t()} | {:error, term()}
  def prepare(base_pdf, opts \\ []) when is_binary(base_pdf) do
    placeholder_size = Keyword.get(opts, :placeholder_size, @default_placeholder_size)
    signing_time = Keyword.get(opts, :signing_time, DateTime.utc_now())
    reason = Keyword.get(opts, :reason)
    location = Keyword.get(opts, :location)
    contact_info = Keyword.get(opts, :contact_info)

    with :ok <- validate_placeholder_size(placeholder_size),
         {:ok, head} <- Reader.parse(base_pdf),
         {:ok, catalog_body} <- Reader.read_catalog_body(base_pdf),
         :ok <- ensure_no_acroform(catalog_body),
         {catalog_num, catalog_gen} <- expect_root(head),
         {:ok, new_catalog} <- merge_catalog_with_acroform(catalog_body, head.size + 1) do
      sig_obj = head.size
      field_obj = head.size + 1
      new_size = head.size + 2

      sig_body = sig_dict_template(placeholder_size, signing_time, reason, location, contact_info)

      field_body =
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) " <>
          "/V #{sig_obj} 0 R /F 132 /Rect [0 0 0 0] >>"

      objects = [
        {catalog_num, catalog_gen, new_catalog},
        {field_obj, 0, field_body},
        {sig_obj, 0, sig_body}
      ]

      {appended_objects, object_offsets} = emit_objects(objects, byte_size(base_pdf))

      xref_offset = byte_size(base_pdf) + byte_size(appended_objects)

      xref_text = render_xref_subsections(object_offsets)

      trailer =
        "trailer\n<< /Size #{new_size} /Root #{catalog_num} #{catalog_gen} R " <>
          "/Prev #{head.startxref} >>\nstartxref\n#{xref_offset}\n%%EOF\n"

      provisional_pdf = base_pdf <> appended_objects <> xref_text <> trailer

      with {:ok, contents_offset} <-
             locate_contents_placeholder(provisional_pdf, object_offsets, sig_obj) do
        contents_length = placeholder_size * 2

        # The /Contents value (a PDF hex string) spans `<...>`
        # inclusively per PDF 1.7 §7.3.4.3. /ByteRange excludes the
        # ENTIRE value, not just the hex digits — `<` and `>` are
        # part of the hole. Pre-0.1.4 we included them as the last
        # byte of the 1st signed chunk / first byte of the 2nd, which
        # is internally consistent (our verify path agrees with our
        # sign path) but disagrees with every other PAdES signer
        # (PDFBox, iText, Acrobat) and is rejected by the EU DSS
        # validator with "/ByteRange dictionary is not consistent".
        lt_offset = contents_offset - 1
        after_gt_offset = contents_offset + contents_length + 1

        byte_range = [
          0,
          lt_offset,
          after_gt_offset,
          byte_size(provisional_pdf) - after_gt_offset
        ]

        case patch_byte_range(provisional_pdf, byte_range) do
          {:ok, final_pdf} ->
            signed_input = extract_signed_input(final_pdf, byte_range)

            {:ok,
             %__MODULE__{
               pdf: final_pdf,
               signed_input: signed_input,
               contents_offset: contents_offset,
               contents_length: contents_length,
               byte_range: byte_range,
               placeholder_size: placeholder_size
             }}

          {:error, _} = err ->
            err
        end
      end
    end
  end

  @doc """
  Splices `cms_der` into the `/Contents` placeholder of a prepared PDF.
  Returns `{:error, {:writer, :cms_der_too_large}}` if the DER exceeds
  the prepared placeholder size; pads with `0x00` bytes (hex `00`)
  otherwise.
  """
  @spec inject_signature(t(), binary()) :: {:ok, binary()} | {:error, term()}
  def inject_signature(%__MODULE__{} = prepared, cms_der) when is_binary(cms_der) do
    if byte_size(cms_der) > prepared.placeholder_size do
      {:error, {:writer, :cms_der_too_large}}
    else
      padded = cms_der <> :binary.copy(<<0>>, prepared.placeholder_size - byte_size(cms_der))
      hex = padded |> Base.encode16(case: :upper)

      pdf = prepared.pdf
      prefix = binary_part(pdf, 0, prepared.contents_offset)

      suffix =
        binary_part(
          pdf,
          prepared.contents_offset + prepared.contents_length,
          byte_size(pdf) - prepared.contents_offset - prepared.contents_length
        )

      {:ok, prefix <> hex <> suffix}
    end
  end

  # --- internals ---

  defp validate_placeholder_size(n) when is_integer(n) and n >= 256 and n <= 1_048_576, do: :ok
  defp validate_placeholder_size(_), do: {:error, {:writer, :placeholder_size_out_of_range}}

  defp expect_root(%Reader.Revision{root: nil}), do: {:error, {:malformed_pdf, :root_missing}}
  defp expect_root(%Reader.Revision{root: {n, g}}), do: {n, g}

  defp ensure_no_acroform(catalog_body) do
    if Regex.match?(~r/\/AcroForm\b/, catalog_body) do
      {:error, {:writer, :existing_acroform_unsupported_in_v1}}
    else
      :ok
    end
  end

  defp merge_catalog_with_acroform(catalog_body, field_obj_num) do
    # Splice "/AcroForm << /Fields [N 0 R] /SigFlags 3 >>" before the
    # closing ">>" of the catalog dict. SigFlags 3 = SignaturesExist (1)
    # | AppendOnly (2) — the latter signals that any further changes
    # must arrive as incremental updates, which is exactly the contract
    # we want PAdES verifiers to enforce.
    new_body =
      "<< " <>
        catalog_body <>
        " /AcroForm << /Fields [#{field_obj_num} 0 R] /SigFlags 3 >>" <>
        " >>"

    {:ok, new_body}
  end

  defp sig_dict_template(placeholder_size, signing_time, reason, location, contact_info) do
    contents_placeholder = "<" <> :binary.copy("0", placeholder_size * 2) <> ">"

    extras =
      [
        {"Reason", reason},
        {"Location", location},
        {"ContactInfo", contact_info}
      ]
      |> Enum.flat_map(fn
        {_, nil} -> []
        {k, v} -> [" /#{k} (#{escape_pdf_string(v)})"]
      end)
      |> IO.iodata_to_binary()

    "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached " <>
      "/ByteRange [0 0000000000 0000000000 0000000000] " <>
      "/Contents #{contents_placeholder} " <>
      "/M (#{format_pdf_date(signing_time)})" <>
      extras <>
      " >>"
  end

  defp format_pdf_date(%DateTime{} = dt) do
    utc = DateTime.shift_zone!(dt, "Etc/UTC")

    "D:" <>
      pad2(utc.year, 4) <>
      pad2(utc.month, 2) <>
      pad2(utc.day, 2) <>
      pad2(utc.hour, 2) <>
      pad2(utc.minute, 2) <>
      pad2(utc.second, 2) <>
      "Z"
  end

  defp pad2(n, width), do: n |> Integer.to_string() |> String.pad_leading(width, "0")

  defp escape_pdf_string(s) do
    s
    |> String.replace("\\", "\\\\")
    |> String.replace("(", "\\(")
    |> String.replace(")", "\\)")
  end

  defp emit_objects(objects, base_offset) do
    Enum.reduce(objects, {<<>>, %{}}, fn {num, gen, body}, {acc, offsets} ->
      header = "\n#{num} #{gen} obj\n"
      footer = "\nendobj\n"
      obj_offset = base_offset + byte_size(acc) + byte_size("\n")
      {acc <> header <> body <> footer, Map.put(offsets, num, obj_offset)}
    end)
  end

  defp render_xref_subsections(object_offsets) do
    sorted = Enum.sort_by(object_offsets, fn {n, _} -> n end)

    body =
      sorted
      |> Enum.map_join("", fn {n, offset} ->
        offset_str = String.pad_leading(Integer.to_string(offset), 10, "0")
        "#{n} 1\n#{offset_str} 00000 n \n"
      end)

    "xref\n" <> body
  end

  defp locate_contents_placeholder(pdf, object_offsets, sig_obj) do
    case Map.fetch(object_offsets, sig_obj) do
      :error ->
        {:error, {:writer, :sig_object_offset_missing}}

      {:ok, sig_offset} ->
        # /Contents <000...> — find the first '<' after "/Contents " in the sig dict
        slice = binary_part(pdf, sig_offset, byte_size(pdf) - sig_offset)

        case :binary.match(slice, "/Contents <") do
          :nomatch ->
            {:error, {:writer, :contents_placeholder_missing}}

          {pos, _len} ->
            # absolute byte offset of the first hex digit
            {:ok, sig_offset + pos + byte_size("/Contents <")}
        end
    end
  end

  defp patch_byte_range(pdf, byte_range) do
    placeholder = "/ByteRange [0 0000000000 0000000000 0000000000]"

    case :binary.match(pdf, placeholder) do
      :nomatch ->
        {:error, {:writer, :byte_range_placeholder_missing}}

      {pos, len} ->
        replacement = format_byte_range(byte_range)

        if byte_size(replacement) != len do
          {:error, {:writer, :byte_range_replacement_width_mismatch}}
        else
          prefix = binary_part(pdf, 0, pos)

          suffix =
            binary_part(pdf, pos + len, byte_size(pdf) - pos - len)

          {:ok, prefix <> replacement <> suffix}
        end
    end
  end

  defp format_byte_range([a, b, c, d]) do
    "/ByteRange [#{a} " <>
      pad10(b) <>
      " " <>
      pad10(c) <>
      " " <>
      pad10(d) <> "]"
  end

  defp pad10(n), do: String.pad_leading(Integer.to_string(n), 10, "0")

  defp extract_signed_input(pdf, [a, b, c, d]) do
    binary_part(pdf, a, b) <> binary_part(pdf, c, d)
  end
end
