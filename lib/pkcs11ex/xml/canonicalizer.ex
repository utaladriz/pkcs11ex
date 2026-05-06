defmodule Pkcs11ex.XML.Canonicalizer do
  @moduledoc """
  Thin wrapper around `Pkcs11ex.XML.C14n.XmerlC14n` — our vendored
  copy of `xmerl_c14n`.

  The Phase 4 plan reserved the option to vendor in-tree if the
  upstream package went unmaintained. The Hex 0.2.0 release crashes
  on OTP 28 (unprefixed-attribute namespace field shape), so we
  vendor + patch in `lib/pkcs11ex/xml/c14n/`. A future pivot to a
  NIF-wrapped `bergshamra` is still a one-file replacement.

  Scope of this module:

    * Canonicalise an `:xmerl` document or fragment into the byte
      sequence that `<DigestValue>` and `<SignatureValue>` are
      computed over.
    * v1 supports only **Exclusive XML Canonicalization 1.0**
      (`http://www.w3.org/2001/10/xml-exc-c14n#`) — the C14N method
      XAdES B-B mandates and the SII DTE shape uses. Inclusive C14N
      and 1.1 are out of scope until a real conformance test argues
      for them.
    * Errors surface as `{:error, {:c14n, reason}}` so the verify
      pipeline can branch on the class atom (per api.md §4.1).
  """

  @typedoc "Canonicalisation method atoms supported by this adapter."
  @type method :: :exclusive_c14n_10

  @typedoc """
  Anything `xmerl_c14n` accepts: a parsed `:xmerl` element record
  (`{:xmlElement, ...}`) or document (`{:xmlDocument, ...}`). For
  binary input use `parse/1` first.
  """
  @type xmerl_node :: tuple()

  @doc """
  Parse an XML binary into an `:xmerl` element. Convenience wrapper
  around `:xmerl_scan.string/2` that returns `:ok | :error` tuples
  rather than crashing on malformed input.

  Returns the root `:xmlElement`. `xmerl_c14n` accepts either an
  element or a document wrapper, but later phases of the sign flow
  need the root element to splice `<Signature>` in as a child, so
  we standardise on returning the element here.
  """
  @spec parse(binary()) :: {:ok, xmerl_node()} | {:error, {:malformed_xml, term()}}
  def parse(xml) when is_binary(xml) do
    {root, _rest} = :xmerl_scan.string(String.to_charlist(xml))
    {:ok, root}
  rescue
    e -> {:error, {:malformed_xml, Exception.message(e)}}
  catch
    :exit, reason -> {:error, {:malformed_xml, reason}}
    kind, reason -> {:error, {:malformed_xml, {kind, reason}}}
  end

  @doc """
  Canonicalise the given `:xmerl` element under Exclusive XML C14N 1.0.

  ## Options

    * `:method` — one of `#{inspect([:exclusive_c14n_10])}`. v1
      rejects anything else with `{:c14n, :unsupported_canonicalization}`.
    * `:inclusive_namespaces` — list of namespace prefixes that
      should NOT be excluded from the canonical form even though
      they're not visibly used. Maps to the
      `<InclusiveNamespaces PrefixList="...">` transform. The
      `xmerl_c14n` API takes this as a charlist list; we accept
      strings and convert.
  """
  @spec canonicalize(xmerl_node(), keyword()) :: {:ok, binary()} | {:error, term()}
  def canonicalize(node, opts \\ []) do
    with :ok <- validate_method(Keyword.get(opts, :method, :exclusive_c14n_10)) do
      inclusive = inclusive_namespaces_charlists(Keyword.get(opts, :inclusive_namespaces, []))

      try do
        bytes = Pkcs11ex.XML.C14n.XmerlC14n.canonicalize!(node, false, inclusive)
        {:ok, bytes}
      rescue
        e -> {:error, {:c14n, Exception.message(e)}}
      catch
        :exit, reason -> {:error, {:c14n, reason}}
        kind, reason -> {:error, {:c14n, {kind, reason}}}
      end
    end
  end

  defp validate_method(:exclusive_c14n_10), do: :ok
  defp validate_method(_), do: {:error, {:c14n, :unsupported_canonicalization}}

  defp inclusive_namespaces_charlists(list) when is_list(list) do
    Enum.map(list, fn
      bin when is_binary(bin) -> String.to_charlist(bin)
      cl when is_list(cl) -> cl
    end)
  end
end
