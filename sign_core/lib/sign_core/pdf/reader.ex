defmodule SignCore.PDF.Reader do
  @moduledoc """
  Minimal PDF trailer / xref scanner for the PAdES adapter.

  Scope is the file-level structure only — the four primitives the
  Phase 4 plan calls out:

    1. Locate `startxref` and the most-recent xref offset.
    2. Parse the text-format xref subsections at that offset.
    3. Extract `/Size`, `/Root`, `/Prev` from the trailer dict.
    4. Walk the `/Prev` chain across revisions.

  Out of scope (deliberately): content streams, encoded streams, page
  resources, font dictionaries, and any indirect-object body. None of
  those are required for incremental signature emission or for
  recomputing the byte-range covered by a `/Sig`.

  Cross-reference streams (PDF 1.5+, `/Type /XRef`) are not handled in
  v1 and surface as `{:error, {:malformed_pdf, :xref_stream_unsupported}}`.
  Per the Phase 4 plan, the writer always emits the legacy text-format
  xref (still legal in PDF 1.7+); the reader is the side that needs to
  tolerate vendor variation, and we accept the limitation until a real
  corpus argues for `lopdf` on the verify path.
  """

  @startxref_window 8_192

  defmodule Revision do
    @moduledoc """
    Parsed view of one xref + trailer pair (one PDF revision).

    Incremental updates form a linked list via `/Prev`; `:prev` is the
    byte offset of the previous revision's xref, or `nil` for the
    original revision.
    """
    defstruct [:startxref, :xref_offsets, :size, :root, :prev]

    @type t :: %__MODULE__{
            startxref: non_neg_integer(),
            xref_offsets: %{optional(non_neg_integer()) => non_neg_integer()},
            size: non_neg_integer() | nil,
            root: {non_neg_integer(), non_neg_integer()} | nil,
            prev: non_neg_integer() | nil
          }
  end

  @typedoc "Reader error. Always carries `:malformed_pdf` as the class atom."
  @type error :: {:malformed_pdf, atom()}

  @doc """
  Returns the byte offset stored in the file's terminating `startxref`
  marker. Searches the last #{@startxref_window} bytes — PDF 1.7 §7.5.5
  requires it within the last 1 KiB but real-world authoring tools emit
  trailing whitespace that pushes the marker further back.
  """
  @spec startxref(binary()) :: {:ok, non_neg_integer()} | {:error, error()}
  def startxref(pdf) when is_binary(pdf) do
    size = byte_size(pdf)
    window = min(size, @startxref_window)
    tail = binary_part(pdf, size - window, window)

    case Regex.scan(~r/startxref\s+(\d+)/, tail, capture: :all_but_first) do
      [] -> {:error, {:malformed_pdf, :startxref_not_found}}
      matches -> {:ok, matches |> List.last() |> hd() |> String.to_integer()}
    end
  end

  @doc """
  Reads the xref table + trailer at the given offset and returns a
  `Revision` describing this PDF revision.
  """
  @spec read_revision(binary(), non_neg_integer()) :: {:ok, Revision.t()} | {:error, error()}
  def read_revision(pdf, offset) when is_binary(pdf) and is_integer(offset) and offset >= 0 do
    if offset >= byte_size(pdf) do
      {:error, {:malformed_pdf, :xref_offset_out_of_range}}
    else
      section = binary_part(pdf, offset, byte_size(pdf) - offset)
      parse_section(section, offset)
    end
  end

  def read_revision(_pdf, _offset), do: {:error, {:malformed_pdf, :xref_offset_out_of_range}}

  @doc """
  Convenience: locate the most-recent xref and read it.
  """
  @spec parse(binary()) :: {:ok, Revision.t()} | {:error, error()}
  def parse(pdf) do
    with {:ok, offset} <- startxref(pdf), do: read_revision(pdf, offset)
  end

  @doc """
  Walks the `/Prev` chain newest-first. The first element is the most
  recent revision (the one `startxref` points at); the last is the
  original.
  """
  @spec revisions(binary()) :: {:ok, [Revision.t()]} | {:error, error()}
  def revisions(pdf) do
    with {:ok, head} <- parse(pdf),
         do: walk_prev(pdf, head, [head], MapSet.new([head.startxref]))
  end

  @doc """
  Returns the next free indirect-object number, derived from the
  most-recent revision's `/Size`. PAdES incremental updates allocate
  fresh object numbers starting here.
  """
  @spec next_object_number(binary()) :: {:ok, non_neg_integer()} | {:error, error()}
  def next_object_number(pdf) do
    case parse(pdf) do
      {:ok, %Revision{size: nil}} -> {:error, {:malformed_pdf, :trailer_size_missing}}
      {:ok, %Revision{size: size}} -> {:ok, size}
      {:error, _} = err -> err
    end
  end

  @doc """
  Reads the textual body of the indirect object at the given offset.
  Returns the bytes between `obj` and `endobj`, trimmed.

  Used by the Writer to extract the catalog dict so an incremental
  update can re-emit it with a merged `/AcroForm` entry. Does not
  parse stream contents; the bytes are returned verbatim.
  """
  @spec read_object_body(binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, error()}
  def read_object_body(pdf, offset) when is_binary(pdf) and is_integer(offset) do
    if offset < 0 or offset >= byte_size(pdf) do
      {:error, {:malformed_pdf, :object_offset_out_of_range}}
    else
      slice = binary_part(pdf, offset, byte_size(pdf) - offset)

      case Regex.run(~r/^\d+\s+\d+\s+obj\b/, slice, return: :index) do
        [{0, header_len}] ->
          after_header = binary_part(slice, header_len, byte_size(slice) - header_len)

          case :binary.match(after_header, "endobj") do
            {pos, _len} ->
              {:ok, after_header |> binary_part(0, pos) |> String.trim()}

            :nomatch ->
              {:error, {:malformed_pdf, :endobj_missing}}
          end

        _ ->
          {:error, {:malformed_pdf, :object_header_invalid}}
      end
    end
  end

  @doc """
  Returns the merged xref offsets across every revision in the PDF —
  newest entry per object number wins (incremental updates override).

  Used by the verify path to enumerate indirect objects by number
  without picking older revisions of objects that were superseded.
  """
  @spec merged_xref_offsets(binary()) ::
          {:ok, %{non_neg_integer() => non_neg_integer()}} | {:error, error()}
  def merged_xref_offsets(pdf) when is_binary(pdf) do
    with {:ok, revs} <- revisions(pdf) do
      # `revisions/1` returns oldest-first; folding left lets the newest
      # revision overwrite previous offsets for the same object number.
      merged =
        Enum.reduce(revs, %{}, fn %Revision{xref_offsets: xs}, acc ->
          Map.merge(acc, xs)
        end)

      {:ok, merged}
    end
  end

  @doc """
  Returns the dict body (the bytes between the object's outer `<<`
  and matching `>>`) for the object at `offset`. `:not_a_dict` for
  objects that don't begin with a dict (streams, primitives).
  """
  @spec read_dict_at(binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, error() | :not_a_dict}
  def read_dict_at(pdf, offset) do
    with {:ok, body} <- read_object_body(pdf, offset) do
      case extract_dict_text(body) do
        {:ok, dict} -> {:ok, dict}
        :error -> {:error, :not_a_dict}
      end
    end
  end

  @doc """
  Returns the list of `{object_number, dict_body}` pairs for every
  indirect object whose body is a dictionary containing `/Type /Sig`.

  This is the canonical way to locate signature dicts: it ignores
  comments, content-stream text that happens to mention `/Type /Sig`,
  and superseded older revisions of the same object number. Each
  returned dict body is bounded — only the dict content between its
  outer `<<` and matching `>>`, suitable for whitespace-tolerant
  regex extraction of `/ByteRange` and `/Contents`.
  """
  @spec signature_dicts(binary()) ::
          {:ok, [{non_neg_integer(), binary()}]} | {:error, error()}
  def signature_dicts(pdf) do
    with {:ok, offsets} <- merged_xref_offsets(pdf) do
      sigs =
        offsets
        |> Enum.sort_by(fn {num, _} -> num end)
        |> Enum.flat_map(fn {num, offset} ->
          case read_dict_at(pdf, offset) do
            {:ok, dict} ->
              if signature_dict?(dict), do: [{num, dict}], else: []

            _ ->
              []
          end
        end)

      {:ok, sigs}
    end
  end

  # PDF names are case-sensitive (ISO 32000 §7.3.5). `/Type /Sig` is
  # the canonical marker for a signature dict; `\b`-style boundaries
  # would prevent `/Sig` matching as a prefix of e.g. `/SigFlags`,
  # but PDF tokens end at any of: whitespace, `/`, `<`, `>`, `[`,
  # `]`, `(`, `)`. We use a character class to be explicit.
  defp signature_dict?(dict_body) do
    Regex.match?(~r{/Type\s+/Sig(?=[\s/<>\[\]()]|$)}, dict_body)
  end

  @doc """
  Returns the catalog dict body (the bytes between `<<` and `>>` of the
  object pointed at by `/Root`). The catalog is what an incremental
  update must re-emit when adding a `/Sig` field — its `/AcroForm` and
  `/Pages` entries need to be preserved.

  Returns `{:error, {:malformed_pdf, :catalog_not_indirect}}` if the
  catalog body isn't a plain dict (rare; would only happen if /Root
  pointed at an object stream).
  """
  @spec read_catalog_body(binary()) :: {:ok, binary()} | {:error, error()}
  def read_catalog_body(pdf) do
    with {:ok, %Revision{root: root, xref_offsets: offsets}} <- parse(pdf) do
      case root do
        nil ->
          {:error, {:malformed_pdf, :root_missing}}

        {num, _gen} ->
          case Map.fetch(offsets, num) do
            :error ->
              {:error, {:malformed_pdf, :root_offset_unknown}}

            {:ok, obj_offset} ->
              case read_object_body(pdf, obj_offset) do
                {:ok, body} -> extract_catalog_dict(body)
                err -> err
              end
          end
      end
    end
  end

  defp extract_catalog_dict(body) do
    case extract_dict_text(body) do
      {:ok, text} -> {:ok, text}
      :error -> {:error, {:malformed_pdf, :catalog_not_indirect}}
    end
  end

  # --- internal ---

  defp parse_section(<<"xref\r\n", rest::binary>>, startxref), do: do_parse(rest, startxref)
  defp parse_section(<<"xref\n", rest::binary>>, startxref), do: do_parse(rest, startxref)

  defp parse_section(<<"xref ", rest::binary>>, startxref),
    do: do_parse(skip_eol(rest), startxref)

  defp parse_section(other, _startxref) do
    cond do
      Regex.match?(~r/^\s*\d+\s+\d+\s+obj\b/, other) ->
        {:error, {:malformed_pdf, :xref_stream_unsupported}}

      true ->
        {:error, {:malformed_pdf, :xref_keyword_missing}}
    end
  end

  defp do_parse(rest, startxref) do
    with {:ok, xref_offsets, after_xref} <- read_subsections(rest, %{}),
         {:ok, trailer_text} <- locate_trailer(after_xref) do
      {:ok,
       %Revision{
         startxref: startxref,
         xref_offsets: xref_offsets,
         size: capture_int(trailer_text, ~r/\/Size\s+(\d+)/),
         root: capture_ref(trailer_text, ~r/\/Root\s+(\d+)\s+(\d+)\s+R/),
         prev: capture_int(trailer_text, ~r/\/Prev\s+(\d+)/)
       }}
    end
  end

  defp read_subsections(<<"trailer", _::binary>> = data, acc), do: {:ok, acc, data}

  defp read_subsections(data, acc) do
    case Regex.run(~r/\A(\d+)\s+(\d+)[ \t]*\r?\n/, data, return: :index) do
      [{0, header_len}, _, _] ->
        header = binary_part(data, 0, header_len)
        rest = binary_part(data, header_len, byte_size(data) - header_len)
        [first_str, count_str] = Regex.run(~r/(\d+)\s+(\d+)/, header, capture: :all_but_first)
        first = String.to_integer(first_str)
        count = String.to_integer(count_str)

        with {:ok, acc2, rest2} <- read_entries(rest, first, count, acc) do
          read_subsections(rest2, acc2)
        end

      _ ->
        {:error, {:malformed_pdf, :xref_subsection_header_invalid}}
    end
  end

  defp read_entries(rest, _first, 0, acc), do: {:ok, acc, rest}

  defp read_entries(<<entry::binary-size(20), rest::binary>>, first, count, acc) do
    case entry do
      <<offset_str::binary-size(10), " ", _gen::binary-size(5), " ", "n", _eol::binary-size(2)>> ->
        case Integer.parse(offset_str) do
          {offset, ""} ->
            read_entries(rest, first + 1, count - 1, Map.put(acc, first, offset))

          _ ->
            {:error, {:malformed_pdf, :xref_entry_unparseable}}
        end

      <<_offset::binary-size(10), " ", _gen::binary-size(5), " ", "f", _eol::binary-size(2)>> ->
        read_entries(rest, first + 1, count - 1, acc)

      _ ->
        {:error, {:malformed_pdf, :xref_entry_malformed}}
    end
  end

  defp read_entries(_, _, _, _), do: {:error, {:malformed_pdf, :xref_truncated}}

  defp locate_trailer(data) do
    case :binary.match(data, "trailer") do
      :nomatch ->
        {:error, {:malformed_pdf, :trailer_keyword_missing}}

      {pos, _len} ->
        after_kw = binary_part(data, pos + 7, byte_size(data) - pos - 7)

        case extract_dict_text(after_kw) do
          {:ok, dict_text} -> {:ok, dict_text}
          :error -> {:error, {:malformed_pdf, :trailer_dict_unparseable}}
        end
    end
  end

  defp extract_dict_text(data) do
    data = ltrim(data)

    case data do
      <<"<<", body::binary>> ->
        case find_matching_close(body, 1, 0) do
          {:ok, end_pos} -> {:ok, binary_part(body, 0, end_pos)}
          :error -> :error
        end

      _ ->
        :error
    end
  end

  defp find_matching_close(_data, 0, pos), do: {:ok, pos - 2}

  defp find_matching_close(<<"<<", rest::binary>>, depth, pos),
    do: find_matching_close(rest, depth + 1, pos + 2)

  defp find_matching_close(<<">>", rest::binary>>, depth, pos),
    do: find_matching_close(rest, depth - 1, pos + 2)

  defp find_matching_close(<<_::binary-size(1), rest::binary>>, depth, pos),
    do: find_matching_close(rest, depth, pos + 1)

  defp find_matching_close(<<>>, _depth, _pos), do: :error

  defp capture_int(text, regex) do
    case Regex.run(regex, text, capture: :all_but_first) do
      [s] -> String.to_integer(s)
      _ -> nil
    end
  end

  defp capture_ref(text, regex) do
    case Regex.run(regex, text, capture: :all_but_first) do
      [num_str, gen_str] -> {String.to_integer(num_str), String.to_integer(gen_str)}
      _ -> nil
    end
  end

  defp ltrim(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: ltrim(rest)
  defp ltrim(rest), do: rest

  defp skip_eol(<<"\r\n", rest::binary>>), do: rest
  defp skip_eol(<<"\n", rest::binary>>), do: rest
  defp skip_eol(<<"\r", rest::binary>>), do: rest
  defp skip_eol(rest), do: rest

  defp walk_prev(_pdf, %Revision{prev: nil}, acc, _seen), do: {:ok, Enum.reverse(acc)}

  defp walk_prev(pdf, %Revision{prev: prev}, acc, seen) do
    cond do
      MapSet.member?(seen, prev) ->
        {:error, {:malformed_pdf, :prev_chain_cycle}}

      true ->
        case read_revision(pdf, prev) do
          {:ok, rev} -> walk_prev(pdf, rev, [rev | acc], MapSet.put(seen, prev))
          {:error, _} = err -> err
        end
    end
  end
end
