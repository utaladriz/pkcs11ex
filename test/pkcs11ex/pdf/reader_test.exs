defmodule Pkcs11ex.PDF.ReaderTest do
  @moduledoc """
  Synthesises minimal PDFs (no real fixtures committed to the repo) and
  exercises every primitive `Pkcs11ex.PDF.Reader` exposes:

    * `startxref/1` — locate `startxref <int>` near the file end.
    * `read_revision/2` — parse the xref table + trailer at an offset.
    * `parse/1` — convenience wrapper.
    * `revisions/1` — walk the `/Prev` chain newest-first.
    * `next_object_number/1` — derive the next free object number.

  The fixtures are valid PDF 1.7 byte-streams with text-format xref
  subsections — the same wire shape `Pkcs11ex.PDF.Writer` will emit in
  step 7. We deliberately keep the fixtures small (no page resources,
  no content streams) because the Reader's contract is file-level
  structure only.
  """

  use ExUnit.Case, async: true

  alias Pkcs11ex.PDF.Reader
  alias Pkcs11ex.PDF.Reader.Revision

  describe "startxref/1" do
    test "extracts the trailing offset from a well-formed PDF" do
      pdf = build_simple_pdf()
      {:ok, offset} = Reader.startxref(pdf)
      assert is_integer(offset) and offset > 0
      assert binary_part(pdf, offset, 4) == "xref"
    end

    test "tolerates trailing whitespace after %%EOF" do
      pdf = build_simple_pdf() <> "\n  \n"
      assert {:ok, offset} = Reader.startxref(pdf)
      assert binary_part(pdf, offset, 4) == "xref"
    end

    test "returns the most recent startxref when several appear" do
      base = build_simple_pdf()
      incremental = build_incremental(base, [{4, "<< /Type /Annot >>"}])
      {:ok, offset} = Reader.startxref(incremental)
      # Most-recent xref is the one in the appended chunk
      assert offset > byte_size(base) - 50
    end

    test "errors when startxref is absent" do
      assert {:error, {:malformed_pdf, :startxref_not_found}} =
               Reader.startxref("not a pdf")
    end
  end

  describe "read_revision/2" do
    test "parses xref entries and trailer dict for the original revision" do
      pdf = build_simple_pdf()
      {:ok, offset} = Reader.startxref(pdf)
      {:ok, %Revision{} = rev} = Reader.read_revision(pdf, offset)

      assert rev.startxref == offset
      assert rev.size == 4
      assert rev.root == {1, 0}
      assert rev.prev == nil
      # Three in-use objects (1, 2, 3) plus the free-list head at 0
      assert map_size(rev.xref_offsets) == 3
      assert Map.has_key?(rev.xref_offsets, 1)
      assert Map.has_key?(rev.xref_offsets, 2)
      assert Map.has_key?(rev.xref_offsets, 3)
    end

    test "extracts /Prev when present" do
      base = build_simple_pdf()
      {:ok, base_offset} = Reader.startxref(base)
      incremental = build_incremental(base, [{4, "<< /Type /Annot >>"}])

      {:ok, head_offset} = Reader.startxref(incremental)
      {:ok, head_rev} = Reader.read_revision(incremental, head_offset)

      assert head_rev.prev == base_offset
      assert head_rev.size == 5
    end

    test "errors on out-of-range offset" do
      pdf = build_simple_pdf()

      assert {:error, {:malformed_pdf, :xref_offset_out_of_range}} =
               Reader.read_revision(pdf, byte_size(pdf) + 10)
    end

    test "errors when xref keyword is missing at the offset" do
      pdf = build_simple_pdf()
      # Point at the PDF header instead of the xref
      assert {:error, {:malformed_pdf, :xref_keyword_missing}} =
               Reader.read_revision(pdf, 0)
    end

    test "detects xref-stream-style cross-references and reports them" do
      # Cross-reference stream looks like "<n> <gen> obj << /Type /XRef ... >>"
      pdf = """
      %PDF-1.5
      4 0 obj
      << /Type /XRef /Size 5 /Root 1 0 R >>
      stream
      endstream
      endobj
      startxref
      9
      %%EOF
      """

      assert {:error, {:malformed_pdf, :xref_stream_unsupported}} =
               Reader.read_revision(pdf, 9)
    end

    test "tolerates xref subsections starting at a non-zero first object" do
      pdf =
        build_pdf_with_subsections([
          {0, [{:free, 0, 65_535}]},
          {3, [{:in_use, 100, 0}]},
          {7, [{:in_use, 200, 0}, {:in_use, 300, 0}]}
        ])

      {:ok, %Revision{xref_offsets: offsets}} = Reader.parse(pdf)
      assert Map.get(offsets, 3) == 100
      assert Map.get(offsets, 7) == 200
      assert Map.get(offsets, 8) == 300
    end
  end

  describe "parse/1" do
    test "round-trips startxref + read_revision in a single call" do
      pdf = build_simple_pdf()
      {:ok, %Revision{} = rev} = Reader.parse(pdf)
      assert rev.size == 4
    end
  end

  describe "revisions/1" do
    test "returns a single-entry list for the original PDF" do
      pdf = build_simple_pdf()
      {:ok, [rev]} = Reader.revisions(pdf)
      assert rev.prev == nil
    end

    test "walks the /Prev chain newest-first across multiple revisions" do
      base = build_simple_pdf()
      r1 = build_incremental(base, [{4, "<< /Type /Annot /Name (rev1) >>"}])
      r2 = build_incremental(r1, [{5, "<< /Type /Annot /Name (rev2) >>"}])

      {:ok, revs} = Reader.revisions(r2)
      assert length(revs) == 3
      [head, mid, original] = revs
      assert head.size == 6
      assert mid.size == 5
      assert original.size == 4
      assert original.prev == nil
    end

    test "detects and refuses /Prev cycles" do
      # Fabricate a PDF where the original's /Prev points back at itself.
      cyclic = build_cyclic_pdf()
      assert {:error, {:malformed_pdf, :prev_chain_cycle}} = Reader.revisions(cyclic)
    end
  end

  describe "next_object_number/1" do
    test "returns /Size of the most-recent revision" do
      pdf = build_simple_pdf()
      assert {:ok, 4} = Reader.next_object_number(pdf)
    end

    test "tracks /Size across incremental updates" do
      base = build_simple_pdf()
      r1 = build_incremental(base, [{4, "<< /Foo true >>"}])
      assert {:ok, 5} = Reader.next_object_number(r1)
    end
  end

  # ============================================================
  # Fixtures
  # ============================================================

  # Builds a 3-object minimal PDF (Catalog + Pages + Page) with an
  # original-revision xref. The objects' bodies are nonsense by design
  # — the Reader never opens them.
  defp build_simple_pdf do
    objects = [
      {1, "<< /Type /Catalog /Pages 2 0 R >>"},
      {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
      {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
    ]

    build_pdf(objects, prev: nil)
  end

  defp build_pdf(objects, opts) do
    prev = Keyword.get(opts, :prev)
    header = "%PDF-1.7\n"

    {body, offsets} =
      Enum.reduce(objects, {header, %{}}, fn {num, content}, {acc, offs} ->
        offset = byte_size(acc)
        obj_bytes = "#{num} 0 obj\n#{content}\nendobj\n"
        {acc <> obj_bytes, Map.put(offs, num, offset)}
      end)

    startxref_offset = byte_size(body)
    size = Enum.max(Map.keys(offsets)) + 1
    entries = build_xref_entries(offsets, size)

    trailer_dict =
      "<< /Size #{size} /Root 1 0 R" <>
        if(prev, do: " /Prev #{prev}", else: "") <>
        " >>"

    body <>
      "xref\n" <>
      "0 #{size}\n" <>
      entries <>
      "trailer\n" <>
      trailer_dict <>
      "\n" <>
      "startxref\n" <>
      "#{startxref_offset}\n" <>
      "%%EOF\n"
  end

  defp build_xref_entries(offsets, size) do
    Enum.map_join(0..(size - 1), "", fn n ->
      case Map.get(offsets, n) do
        nil ->
          if n == 0, do: "0000000000 65535 f \n", else: "0000000000 00000 f \n"

        offset ->
          offset_str = String.pad_leading(Integer.to_string(offset), 10, "0")
          "#{offset_str} 00000 n \n"
      end
    end)
  end

  # Appends an incremental update to `base` adding the given new
  # objects. The new xref's /Prev points at the previous revision.
  defp build_incremental(base, new_objects) do
    {:ok, prev_offset} = Reader.startxref(base)
    {:ok, prev_rev} = Reader.read_revision(base, prev_offset)
    prev_size = prev_rev.size

    {appended, offsets} =
      Enum.reduce(new_objects, {base, %{}}, fn {num, content}, {acc, offs} ->
        offset = byte_size(acc)
        obj_bytes = "#{num} 0 obj\n#{content}\nendobj\n"
        {acc <> obj_bytes, Map.put(offs, num, offset)}
      end)

    new_startxref = byte_size(appended)
    new_size = max(prev_size, Enum.max(Map.keys(offsets)) + 1)

    # Subsection per object — minimal incremental updates only describe
    # the object numbers they add or change. This is the standard pattern.
    subsections =
      offsets
      |> Enum.sort_by(fn {n, _} -> n end)
      |> Enum.map_join("", fn {n, offset} ->
        offset_str = String.pad_leading(Integer.to_string(offset), 10, "0")
        "#{n} 1\n#{offset_str} 00000 n \n"
      end)

    appended <>
      "xref\n" <>
      subsections <>
      "trailer\n" <>
      "<< /Size #{new_size} /Root 1 0 R /Prev #{prev_offset} >>\n" <>
      "startxref\n" <>
      "#{new_startxref}\n" <>
      "%%EOF\n"
  end

  # PDF whose trailer's /Prev points at its own startxref, simulating a
  # malformed/forged file. Used to assert the cycle guard fires.
  defp build_cyclic_pdf do
    objects = [{1, "<< /Type /Catalog >>"}]

    header = "%PDF-1.7\n"

    {body, offsets} =
      Enum.reduce(objects, {header, %{}}, fn {num, content}, {acc, offs} ->
        offset = byte_size(acc)
        obj_bytes = "#{num} 0 obj\n#{content}\nendobj\n"
        {acc <> obj_bytes, Map.put(offs, num, offset)}
      end)

    startxref_offset = byte_size(body)
    size = 2
    entries = build_xref_entries(offsets, size)

    body <>
      "xref\n" <>
      "0 #{size}\n" <>
      entries <>
      "trailer\n" <>
      "<< /Size #{size} /Root 1 0 R /Prev #{startxref_offset} >>\n" <>
      "startxref\n" <>
      "#{startxref_offset}\n" <>
      "%%EOF\n"
  end

  # Builds a PDF where the original xref has multiple subsections (e.g.
  # gaps in object numbering). `subsections` is a list of `{first, [entries]}`
  # tuples with each entry as `{:free | :in_use, offset, gen}`.
  defp build_pdf_with_subsections(subsections) do
    # Place dummy objects at the offsets the entries claim
    body = "%PDF-1.7\n%filler-#{String.duplicate("a", 280)}\n"
    startxref_offset = byte_size(body)

    subsection_text =
      Enum.map_join(subsections, "", fn {first, entries} ->
        header = "#{first} #{length(entries)}\n"

        entries_text =
          Enum.map_join(entries, "", fn
            {:free, offset, gen} ->
              "#{String.pad_leading(Integer.to_string(offset), 10, "0")} " <>
                "#{String.pad_leading(Integer.to_string(gen), 5, "0")} f \n"

            {:in_use, offset, gen} ->
              "#{String.pad_leading(Integer.to_string(offset), 10, "0")} " <>
                "#{String.pad_leading(Integer.to_string(gen), 5, "0")} n \n"
          end)

        header <> entries_text
      end)

    size =
      subsections
      |> Enum.flat_map(fn {first, entries} ->
        Enum.with_index(entries, fn _, i -> first + i end)
      end)
      |> Enum.max()
      |> Kernel.+(1)

    body <>
      "xref\n" <>
      subsection_text <>
      "trailer\n" <>
      "<< /Size #{size} /Root 1 0 R >>\n" <>
      "startxref\n" <>
      "#{startxref_offset}\n" <>
      "%%EOF\n"
  end
end
