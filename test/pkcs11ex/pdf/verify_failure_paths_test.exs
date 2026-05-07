defmodule SignCore.PDF.VerifyFailurePathsTest do
  @moduledoc """
  Verify-side failure paths that do **not** require a signed PDF as
  input — i.e., they don't need SoftHSM to produce a fixture. The
  happy-path round-trip and tampered-byte detection live in
  `pdf_softhsm_test.exs` because they need real HSM-produced
  signatures.
  """

  use ExUnit.Case, async: false

  alias Pkcs11ex.PDF

  describe "verify/2 surface errors" do
    test "PDF with no /Sig dict surfaces :no_signature" do
      assert {:error, :no_signature} = PDF.verify(build_unsigned_pdf())
    end

    test "non-PDF binary surfaces :no_signature" do
      assert {:error, :no_signature} = PDF.verify("definitely not a pdf")
    end

    test "PDF carrying two real /Sig objects surfaces :multiple_signatures_unsupported_in_v1" do
      # Two indirect objects, both with /Type /Sig, both registered in
      # the xref. Bodies are the smallest-possible valid sig-shaped
      # dicts (the verify path doesn't reach signature math because
      # the multi-sig gate trips first).
      pdf =
        build_pdf_with_objects([
          {1, "<< /Type /Catalog /Pages 2 0 R >>"},
          {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
          {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"},
          {4, "<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>"},
          {5, "<< /Type /Sig /ByteRange [0 4 5 6] /Contents <FF> >>"}
        ])

      assert {:error, :multiple_signatures_unsupported_in_v1} = PDF.verify(pdf)
    end

    test "trailing free-text mentioning /ByteRange after %%EOF is ignored" do
      # Pre-fix this would falsely trip multi-signature detection
      # because the regex matched bytes outside the xref. The Reader-
      # based parser walks indirect objects via xref, so trailing
      # comments / free text are correctly ignored.
      pdf =
        build_unsigned_pdf() <>
          "\n%sig1 /ByteRange [0 1 2 3] /Contents <00>\n"

      assert {:error, :no_signature} = PDF.verify(pdf)
    end

    test "/Contents that isn't valid hex inside a real /Type /Sig surfaces :malformed_signature_contents" do
      pdf =
        build_pdf_with_objects([
          {1, "<< /Type /Catalog /Pages 2 0 R >>"},
          {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
          {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"},
          {4, "<< /Type /Sig /ByteRange [0 1 2 3] /Contents <ZZ> >>"}
        ])

      assert {:error, :malformed_signature_contents} = PDF.verify(pdf)
    end
  end

  defp build_unsigned_pdf do
    build_pdf_with_objects([
      {1, "<< /Type /Catalog /Pages 2 0 R >>"},
      {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
      {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
    ])
  end

  defp build_pdf_with_objects(objects) do
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
end
