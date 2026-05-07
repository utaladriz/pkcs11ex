defmodule SignCore.PDF.WriterTest do
  @moduledoc """
  Black-box tests for `SignCore.PDF.Writer`.

  All tests build the base PDF via the same fixture builder used in
  `SignCore.PDF.ReaderTest`. We deliberately do NOT verify against
  `pdfsig` or `verifypdf` here — those are step 8 / 9 territory and
  would require those external tools in CI. Instead this suite proves
  the structural contract:

    * the writer produces a PDF the Reader can re-parse,
    * `/ByteRange` partitions the file into exactly two signed regions
      whose union is the whole file minus the hex placeholder,
    * the placeholder is exactly `2 * placeholder_size` ASCII chars,
    * `/Prev` points at the original `startxref`,
    * `inject_signature/2` patches the placeholder in place without
      shifting any other byte.
  """

  use ExUnit.Case, async: true

  alias SignCore.PDF.{Reader, Writer}

  describe "prepare/2 — happy path" do
    test "produces an incremental update the Reader can re-parse" do
      base = build_simple_pdf()
      assert {:ok, %Writer{} = prepared} = Writer.prepare(base)

      assert {:ok, [head, original]} = Reader.revisions(prepared.pdf)
      assert original.size == 4
      assert head.size == 6
      assert head.prev != nil
    end

    test "byte_range partitions the PDF cleanly around the hex placeholder" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base, placeholder_size: 1024)

      [a, b, c, d] = prepared.byte_range
      assert a == 0
      assert b == prepared.contents_offset
      assert c == prepared.contents_offset + prepared.contents_length
      assert d == byte_size(prepared.pdf) - c

      # The bytes inside [b..c) are exactly the placeholder hex (zeros)
      placeholder_region = binary_part(prepared.pdf, b, c - b)
      assert byte_size(placeholder_region) == prepared.contents_length
      assert placeholder_region == :binary.copy("0", prepared.contents_length)
    end

    test "signed_input is exactly the concatenation of the two byte_range slices" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base)

      [a, b, c, d] = prepared.byte_range

      expected =
        binary_part(prepared.pdf, a, b) <>
          binary_part(prepared.pdf, c, d)

      assert prepared.signed_input == expected
    end

    test "trailer /Prev points at the original startxref" do
      base = build_simple_pdf()
      {:ok, base_offset} = Reader.startxref(base)

      {:ok, prepared} = Writer.prepare(base)
      {:ok, head} = Reader.parse(prepared.pdf)

      assert head.prev == base_offset
    end

    test "trailer /Size is original_size + 2" do
      base = build_simple_pdf()
      {:ok, base_rev} = Reader.parse(base)

      {:ok, prepared} = Writer.prepare(base)
      {:ok, new_rev} = Reader.parse(prepared.pdf)

      assert new_rev.size == base_rev.size + 2
    end

    test "placeholder_size of 256 yields a 512-char hex region" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base, placeholder_size: 256)
      assert prepared.contents_length == 512
    end

    test "the /Sig dict contains a fixed-width /ByteRange after patching" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base)

      [_a, b, c, d] = prepared.byte_range
      expected = "/ByteRange [0 #{pad10(b)} #{pad10(c)} #{pad10(d)}]"
      assert :binary.match(prepared.pdf, expected) != :nomatch
    end

    test "embeds optional /Reason, /Location, /ContactInfo when supplied" do
      base = build_simple_pdf()

      {:ok, prepared} =
        Writer.prepare(base,
          reason: "Test signature",
          location: "Santiago",
          contact_info: "ops@example.com"
        )

      assert :binary.match(prepared.pdf, "/Reason (Test signature)") != :nomatch
      assert :binary.match(prepared.pdf, "/Location (Santiago)") != :nomatch
      assert :binary.match(prepared.pdf, "/ContactInfo (ops@example.com)") != :nomatch
    end

    test "embeds /M with the supplied signing_time in PDF date format" do
      base = build_simple_pdf()
      ts = ~U[2026-05-06 14:05:30Z]

      {:ok, prepared} = Writer.prepare(base, signing_time: ts)
      assert :binary.match(prepared.pdf, "/M (D:20260506140530Z)") != :nomatch
    end

    test "escapes parentheses and backslashes inside literal strings" do
      base = build_simple_pdf()

      {:ok, prepared} =
        Writer.prepare(base, reason: "(parenthetical) and \\backslash")

      # Parens are escaped so the PDF string parser sees them as literals
      assert :binary.match(prepared.pdf, "/Reason (\\(parenthetical\\) and \\\\backslash)") !=
               :nomatch
    end
  end

  describe "prepare/2 — errors" do
    test "refuses to operate on a base PDF that already has /AcroForm" do
      pdf = build_pdf_with_acroform()
      assert {:error, {:writer, :existing_acroform_unsupported_in_v1}} = Writer.prepare(pdf)
    end

    test "refuses placeholder_size below the lower bound" do
      base = build_simple_pdf()

      assert {:error, {:writer, :placeholder_size_out_of_range}} =
               Writer.prepare(base, placeholder_size: 100)
    end

    test "refuses placeholder_size above the upper bound" do
      base = build_simple_pdf()

      assert {:error, {:writer, :placeholder_size_out_of_range}} =
               Writer.prepare(base, placeholder_size: 10_000_000)
    end

    test "propagates Reader errors when the base PDF is malformed" do
      assert {:error, {:malformed_pdf, _}} = Writer.prepare("not a pdf")
    end
  end

  describe "inject_signature/2" do
    test "splices CMS DER into the placeholder and pads with zeros" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base, placeholder_size: 256)

      cms = :crypto.strong_rand_bytes(100)
      {:ok, final_pdf} = Writer.inject_signature(prepared, cms)

      # File length unchanged — splice is byte-for-byte
      assert byte_size(final_pdf) == byte_size(prepared.pdf)

      # The hex of cms appears at contents_offset
      hex = Base.encode16(cms, case: :upper)
      injected = binary_part(final_pdf, prepared.contents_offset, byte_size(hex))
      assert injected == hex

      # The remaining placeholder bytes are zero-byte hex ("00...")
      tail_pad =
        binary_part(
          final_pdf,
          prepared.contents_offset + byte_size(hex),
          prepared.contents_length - byte_size(hex)
        )

      expected_pad = :binary.copy("00", prepared.placeholder_size - byte_size(cms))
      assert tail_pad == expected_pad
    end

    test "leaves bytes outside the placeholder untouched" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base)

      cms = :crypto.strong_rand_bytes(prepared.placeholder_size)
      {:ok, final_pdf} = Writer.inject_signature(prepared, cms)

      [_a, b, c, d] = prepared.byte_range
      pre = binary_part(prepared.pdf, 0, b)
      post = binary_part(prepared.pdf, c, d)
      assert binary_part(final_pdf, 0, b) == pre
      assert binary_part(final_pdf, c, d) == post
    end

    test "signed_input bytes survive injection — they are by construction outside the placeholder" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base)

      cms = :crypto.strong_rand_bytes(prepared.placeholder_size)
      {:ok, final_pdf} = Writer.inject_signature(prepared, cms)

      [a, b, c, d] = prepared.byte_range
      reconstructed = binary_part(final_pdf, a, b) <> binary_part(final_pdf, c, d)
      assert reconstructed == prepared.signed_input
    end

    test "rejects a CMS DER bigger than the prepared placeholder" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base, placeholder_size: 256)
      oversized = :crypto.strong_rand_bytes(257)
      assert {:error, {:writer, :cms_der_too_large}} = Writer.inject_signature(prepared, oversized)
    end

    test "produces a final PDF whose Reader-side revision chain is intact" do
      base = build_simple_pdf()
      {:ok, prepared} = Writer.prepare(base)
      cms = :crypto.strong_rand_bytes(prepared.placeholder_size)
      {:ok, final_pdf} = Writer.inject_signature(prepared, cms)

      assert {:ok, [head, original]} = Reader.revisions(final_pdf)
      assert head.size == 6
      assert original.prev == nil
    end
  end

  # ============================================================
  # Fixtures (mirrored from ReaderTest for parity)
  # ============================================================

  defp pad10(n), do: n |> Integer.to_string() |> String.pad_leading(10, "0")

  defp build_simple_pdf do
    objects = [
      {1, "<< /Type /Catalog /Pages 2 0 R >>"},
      {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
      {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
    ]

    build_pdf(objects)
  end

  defp build_pdf_with_acroform do
    objects = [
      {1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] >> >>"},
      {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
      {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
    ]

    build_pdf(objects)
  end

  defp build_pdf(objects) do
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
      "xref\n" <>
      "0 #{size}\n" <>
      entries <>
      "trailer\n<< /Size #{size} /Root 1 0 R >>\n" <>
      "startxref\n#{startxref_offset}\n%%EOF\n"
  end
end
