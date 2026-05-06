defmodule Pkcs11ex.XML.C14n.XmerlC14n do
  @moduledoc """
  Vendored copy of `xmerl_c14n` (DoggettCK/xmerl_c14n on Hex, derived
  from esaml's Erlang implementation).

  Functions for performing XML canonicalization (c14n), as specified
  at [http://www.w3.org/TR/xml-c14n](http://www.w3.org/TR/xml-c14n).

  ## Why vendored

  The Hex package (last release Sep 2019) crashes on OTP 28 when an
  unprefixed attribute carries `[]` in its namespace field rather
  than `{:xmlNamespace, [], []}`. We vendor + patch rather than
  carrying a broken dependency.

  ## Local edits vs. upstream Hex 0.2.0 (BSD-2-Clause)

    * Module renamed `XmerlC14n` → `Pkcs11ex.XML.C14n.XmerlC14n`.
    * `do_canonical_name/3` gains a clause for non-`:xmlNamespace`
      namespace fields — returns the bare local name (exc-c14n's
      rule for unprefixed attributes living in no namespace).

  Original copyright in `LICENSE.md` in this directory. The above
  patches are © 2026 the pkcs11ex maintainers, BSD-2-Clause-compatible.
  """

  ### TYPE DECLARATIONS
  @typep xml_attribute :: {:xmlAttribute, term, term, term, term, term, term, term, term, term}
  @typep xml_comment :: {:xmlComment, term, term, term, term}
  @typep xml_decl :: {:xmlDecl, term, term, term, term}
  @typep xml_document :: {:xmlDocument, term}
  @typep xml_element ::
           {:xmlElement, term, term, term, term, term, term, term, term, term, term, term}
  @typep xml_namespace :: {:xmlNamespace, term, term}
  @typep xml_ns_node :: {:xmlNsNode, term, term, term, term}
  @typep xml_pi :: {:xmlPI, term, term, term, term}
  @typep xml_text :: {:xmlText, term, term, term, term, term}
  @typep xml_type ::
           xml_attribute
           | xml_comment
           | xml_decl
           | xml_document
           | xml_element
           | xml_namespace
           | xml_ns_node
           | xml_pi
           | xml_text

  # Guess who got bit by xmerl making empty strings into atoms?
  defguardp is_empty(item) when item in [:"", '', ""]

  ### PUBLIC API

  @doc """
  Given an `xmerl` XML tuple (element/attribute/etc...) or string
  representation of XML, returns the canonical binary version of the XML it
  represents.

  Returns either `{:ok, String.t()}` if canonicalized successfully, or
  `{:error, {:failed_canonicalization, term}}` if canonicalization failed.

  If the `preserve_comments` argument is true, preserves comments in the output. Any
  namespace prefixes listed in `inclusive_namespaces` will be left as they are and not
  modified during canonicalization.

  ```
  # Given xml
  <!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>
    <doc>
    <e1   />
    <e2   ></e2>
    <e3   name = "elem3"   id="elem3"   />
    <e4   name="elem4"   id="elem4"   ></e4>
    <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
    <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
        <e8 xmlns="" xmlns:a="http://www.w3.org">
          <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
        </e8>
      </e7>
    </e6>
    </doc>

  iex> {:ok, canonicalized_xml} = XmerlC14n.canonicalize(xml)
  iex> IO.puts(canonicalized_xml)
  <doc>
      <e1></e1>
      <e2></e2>
      <e3 id="elem3" name="elem3"></e3>
      <e4 id="elem4" name="elem4"></e4>
      <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
      <e6>
        <e7 xmlns="http://www.ietf.org">
            <e8 xmlns="">
              <e9></e9>
            </e8>
        </e7>
      </e6>
  </doc>
  ```
  """
  @spec canonicalize(entity :: xml_type | String.t()) ::
          {:ok, String.t()} | {:error, {:failed_canonicalization, term}}
  def canonicalize(entity), do: canonicalize(entity, true)

  @spec canonicalize(entity :: xml_type | String.t(), preserve_comments :: boolean()) ::
          {:ok, String.t()} | {:error, {:failed_canonicalization, term}}
  def canonicalize(entity, preserve_comments), do: canonicalize(entity, preserve_comments, [])

  @spec canonicalize(
          entity :: xml_type | String.t(),
          preserve_comments :: boolean(),
          inclusive_namespaces :: []
        ) :: {:ok, String.t()} | {:error, {:failed_canonicalization, term}}
  def canonicalize(entity, preserve_comments, inclusive_namespaces) do
    canonicalized_xml =
      entity
      |> maybe_parse_xml_document()
      |> do_canonicalize([], [], preserve_comments, inclusive_namespaces)

    {:ok, canonicalized_xml}
  rescue
    e in ArgumentError ->
      {:error, {:failed_canonicalization, e.message}}
  end

  @doc """
  Given an `xmerl` XML tuple (element/attribute/etc...) or string
  representation of XML, returns the canonical binary version of the XML it
  represents.

  Returns either `String.t()` if canonicalized successfully, or raises an
  `ArgumentError` if canonicalization failed.

  If the `preserve_comments` argument is true, preserves comments in the output. Any
  namespace prefixes listed in `inclusive_namespaces` will be left as they are and not
  modified during canonicalization.

  ```
  # Given xml
  <!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>
    <doc>
    <e1   />
    <e2   ></e2>
    <e3   name = "elem3"   id="elem3"   />
    <e4   name="elem4"   id="elem4"   ></e4>
    <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
    <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
        <e8 xmlns="" xmlns:a="http://www.w3.org">
          <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
        </e8>
      </e7>
    </e6>
    </doc>

  iex> XmerlC14n.canonicalize!(xml) |> IO.puts
  <doc>
    <e1></e1>
    <e2></e2>
    <e3 id="elem3" name="elem3"></e3>
    <e4 id="elem4" name="elem4"></e4>
    <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
    <e6>
      <e7 xmlns="http://www.ietf.org">
        <e8 xmlns="">
          <e9></e9>
        </e8>
      </e7>
    </e6>
  </doc>
  ```
  """
  @spec canonicalize!(entity :: xml_type | String.t()) :: String.t()
  def canonicalize!(entity), do: canonicalize!(entity, true)

  @spec canonicalize!(entity :: xml_type | String.t(), preserve_comments :: boolean()) ::
          String.t()
  def canonicalize!(entity, preserve_comments), do: canonicalize!(entity, preserve_comments, [])

  @spec canonicalize!(
          entity :: xml_type | String.t(),
          preserve_comments :: boolean(),
          inclusive_namespaces :: []
        ) :: String.t()
  def canonicalize!(entity, preserve_comments, inclusive_namespaces) do
    entity
    |> maybe_parse_xml_document()
    |> do_canonicalize([], [], preserve_comments, inclusive_namespaces)
  end

  ### PRIVATE API
  # Support canonicalizing a string of XML
  defp maybe_parse_xml_document(string) when is_binary(string) do
    {document, _} =
      string
      |> to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true, document: true)

    document
  end

  defp maybe_parse_xml_document(non_string), do: non_string

  # Make XML OK to eat, in a non-quoted situation
  defp xml_safe_string(term) do
    xml_safe_string(term, false)
  end

  # Make XML OK to eat
  defp xml_safe_string(atom, quotes) when is_atom(atom) do
    atom
    |> atom_to_string
    |> xml_safe_string(quotes)
  end

  defp xml_safe_string(term, quotes) when not is_binary(term) do
    term
    |> to_string
    |> xml_safe_string(quotes)
  end

  defp xml_safe_string("", _quotes), do: ""

  defp xml_safe_string("\n" <> rest, false) do
    "\n" <> xml_safe_string(rest, false)
  end

  defp xml_safe_string(<<next::binary-size(1), rest::binary>>, quotes) when next < " " do
    hex_entity(next) <> xml_safe_string(rest, quotes)
  end

  defp xml_safe_string("\"" <> rest, true) do
    "&quot;" <> xml_safe_string(rest, true)
  end

  defp xml_safe_string("&" <> rest, quotes) do
    "&amp;" <> xml_safe_string(rest, quotes)
  end

  defp xml_safe_string("<" <> rest, quotes) do
    "&lt;" <> xml_safe_string(rest, quotes)
  end

  defp xml_safe_string(">" <> rest, false) do
    "&gt;" <> xml_safe_string(rest, false)
  end

  defp xml_safe_string(<<next::binary-size(1), rest::binary>>, quotes) do
    next <> xml_safe_string(rest, quotes)
  end

  defp xml_safe_string(term, quotes) do
    xml_safe_string(inspect(term), quotes)
  end

  # Given an `xmerl` Attribute or Element, returns the canonical URI name.
  defp canonical_name({:xmlAttribute, _, _, {prefix, name}, namespace, _, _, _, _, _}) do
    do_canonical_name(prefix, name, namespace)
  end

  defp canonical_name({:xmlAttribute, name, _, _, namespace, _, _, _, _, _}) do
    do_canonical_name("", name, namespace)
  end

  defp canonical_name({:xmlElement, _, _, {prefix, name}, namespace, _, _, _, _, _, _, _}) do
    do_canonical_name(prefix, name, namespace)
  end

  defp canonical_name({:xmlElement, name, _, _, namespace, _, _, _, _, _, _, _}) do
    do_canonical_name("", name, namespace)
  end

  # Returns the canonical namespace-URI-prefix-resolved version of an XML name
  defp do_canonical_name(prefix, name, {:xmlNamespace, default, nodes} = namespace) do
    with {:ok, namespace_part} <- find_namespace_by_prefix(prefix, default, nodes) do
      namespace_part <> atom_to_string(name)
    else
      {:error, :namespace_not_found} ->
        bad_args = %{prefix: prefix, namespace: namespace}

        raise ArgumentError, message: "namespace not found: #{inspect(bad_args)}"
    end
  end

  # OTP 28 patch: xmerl emits `[]` for the namespace field of an
  # unprefixed attribute that doesn't inherit a default namespace.
  # The exc-c14n rule for that case is "the canonical name is the
  # local name alone" — there's nothing to resolve.
  defp do_canonical_name(_prefix, name, _namespace), do: atom_to_string(name)

  defp find_namespace_by_prefix(prefix, default, _namespace_nodes) when is_empty(prefix),
    do: {:ok, atom_to_string(default)}

  defp find_namespace_by_prefix(_prefix, _default, []), do: {:error, :namespace_not_found}

  defp find_namespace_by_prefix(prefix, _default, [{prefix, uri} | _]),
    do: {:ok, atom_to_string(uri)}

  defp find_namespace_by_prefix(prefix, default, [{_, _} | rest]) do
    find_namespace_by_prefix(prefix, default, rest)
  end

  defp atom_to_string(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp atom_to_string(term) when not is_binary(term), do: to_string(term)
  defp atom_to_string(term), do: term

  # Compares two XML attributes for c14n purposes
  defp attr_lte(
         {:xmlAttribute, _, _, _, _, _, _, _, _, _} = attr_a,
         {:xmlAttribute, _, _, _, _, _, _, _, _, _} = attr_b
       ) do
    a_prefixed? = namespace_prefixed?(attr_a)
    b_prefixed? = namespace_prefixed?(attr_b)

    case {a_prefixed?, b_prefixed?} do
      {true, false} ->
        false

      {false, true} ->
        true

      _ ->
        canon_a = canonical_name(attr_a)
        canon_b = canonical_name(attr_b)

        canon_a <= canon_b
    end
  end

  defp namespace_prefixed?({:xmlAttribute, _, _, {_, _}, _, _, _, _, _, _}), do: true
  defp namespace_prefixed?({:xmlAttribute, _, _, _, _, _, _, _, _, _}), do: false

  # Cleans out all namespace definitions from an attribute list and returns it sorted
  defp clean_sort_attrs(attrs) when is_list(attrs) do
    attrs
    |> Enum.filter(&filter_default_ns/1)
    |> Enum.sort(&attr_lte/2)
  end

  defp filter_default_ns({:xmlAttribute, _, _, {:xmlns, _}, _, _, _, _, _, _}), do: false
  defp filter_default_ns({:xmlAttribute, :xmlns, _, _, _, _, _, _, _, _}), do: false
  defp filter_default_ns({:xmlAttribute, _, _, {'xmlns', _}, _, _, _, _, _, _}), do: false
  defp filter_default_ns({:xmlAttribute, 'xmlns', _, _, _, _, _, _, _, _}), do: false
  defp filter_default_ns({:xmlAttribute, _, _, _, _, _, _, _, _, _}), do: true

  # Returns the list of namespace prefixes "needed" by an element in canonical form
  defp needed_namespaces(
         {:xmlElement, _, _, nsinfo, _, _, _, attrs, _, _, _, _},
         inclusive_namespaces
       )
       when is_list(inclusive_namespaces) do
    needed =
      case nsinfo do
        {prefix, _} ->
          [prefix]

        _ ->
          []
      end

    Enum.reduce(attrs, needed, fn attribute, namespaces ->
      add_needed_namespaces(attribute, namespaces, inclusive_namespaces)
    end)
  end

  defp add_needed_namespaces(
         {:xmlAttribute, _, _, {'xmlns', prefix}, _, _, _, _, _, _},
         needed_namespaces,
         inclusive_namespaces
       ) do
    if prefix in inclusive_namespaces do
      [prefix | needed_namespaces]
    else
      needed_namespaces
    end
  end

  defp add_needed_namespaces(
         {:xmlAttribute, _, _, {namespace, _}, _, _, _, _, _, _},
         needed_namespaces,
         _inclusive_namespaces
       ) do
    if namespace in needed_namespaces do
      needed_namespaces
    else
      [namespace | needed_namespaces]
    end
  end

  defp add_needed_namespaces(
         {:xmlAttribute, _, _, _, _, _, _, _, _, _},
         needed_namespaces,
         _inclusive_namespaces
       ) do
    needed_namespaces
  end

  defp hex_entity(<<bin::binary-size(1)>>) do
    hex =
      bin
      |> Base.encode16()
      |> String.trim_leading("0")

    "&#x#{hex};"
  end

  defp do_canonicalize(
         {:xmlText, _, _, _, value, _},
         _known_namespaces,
         _active_namespaces,
         _preserve_comments,
         _inclusive_namespaces
       ) do
    xml_safe_string(value)
  end

  defp do_canonicalize(
         {:xmlComment, _, _, _, _},
         _known_namespaces,
         _active_namespaces,
         false,
         _inclusive_namespaces
       ),
       do: ""

  defp do_canonicalize(
         {:xmlComment, _, _, _, value},
         _known_namespaces,
         _active_namespaces,
         true,
         _inclusive_namespaces
       ) do
    safe_comment_value = xml_safe_string(value)

    ~s{<!--#{safe_comment_value}-->}
  end

  defp do_canonicalize(
         {:xmlPI, name, _, _, value},
         _known_namespaces,
         _active_namespaces,
         _preserve_comments,
         _inclusive_namespaces
       ) do
    name_string =
      name
      |> atom_to_string()
      |> String.trim()

    value_string =
      value
      |> atom_to_string()

    case String.trim(value_string) do
      "" ->
        ~s{<?#{name_string}?>}

      _ ->
        # NOTE: Don't used trimmed because whitespace is important if not blank
        ~s{<?#{name_string} #{value_string}?>}
    end
  end

  defp do_canonicalize(
         {:xmlDocument, children},
         known_namespaces,
         active_namespaces,
         preserve_comments,
         inclusive_namespaces
       ) do
    children
    |> Enum.map(fn child ->
      do_canonicalize(
        child,
        known_namespaces,
        active_namespaces,
        preserve_comments,
        inclusive_namespaces
      )
    end)
    |> Enum.join("\n")
    |> String.trim()
  end

  defp do_canonicalize(
         {:xmlElement, name, _, nsinfo, {:xmlNamespace, default, nodes}, _, _, attrs, children, _,
          _, _} = entity,
         existing_known_namespaces,
         existing_active_namespaces,
         preserve_comments,
         inclusive_namespaces
       ) do
    {current_active_namespaces, parent_default} =
      case existing_active_namespaces do
        [{:default, p} | rest] ->
          {rest, p}

        other ->
          {other, ""}
      end

    # Add any namespaces this element has that we haven't seen before
    known_namespaces = add_current_namespaces_to_known(nodes, existing_known_namespaces)

    # Now figure out the minimum set of namespaces we need at this level
    needed_namespaces = needed_namespaces(entity, inclusive_namespaces)

    # and all of the attributes that aren't xmlns
    sorted_attributes = clean_sort_attrs(attrs)

    # Need to append any "xmlns:" that the parent didn't have (i.e. aren't
    # in current_active_namespaces), but that we need
    new_namespaces = needed_namespaces -- current_active_namespaces
    new_active_namespaces = current_active_namespaces ++ new_namespaces

    current_active_namespaces = current_level_active_namespaces(default, new_active_namespaces)

    tag = name |> atom_to_string |> tag_name(nsinfo)

    opening_tag =
      open_tag(
        tag,
        current_active_namespaces,
        new_namespaces,
        default,
        parent_default,
        sorted_attributes,
        known_namespaces
      )

    concatenated_children =
      Enum.map(children, fn child ->
        do_canonicalize(
          child,
          known_namespaces,
          current_active_namespaces,
          preserve_comments,
          inclusive_namespaces
        )
      end)

    closing_tag = close_tag(tag)

    [
      opening_tag,
      concatenated_children,
      closing_tag
    ]
    |> Enum.join()
  end

  # Don't care about any other elements
  defp do_canonicalize(
         _entity,
         _known_namespaces,
         _active_namespaces,
         _preserve_comments,
         _inclusive_namespaces
       ),
       do: ""

  defp add_current_namespaces_to_known(current_namespaces, known_namespaces) do
    Enum.reduce(current_namespaces, known_namespaces, fn {namespace, uri}, namespaces ->
      if :proplists.is_defined(namespace, namespaces) do
        namespaces
      else
        [{namespace, atom_to_string(uri)} | namespaces]
      end
    end)
  end

  defp current_level_active_namespaces(default, active_namespaces) when not is_empty(default) do
    [{:default, default} | active_namespaces]
  end

  defp current_level_active_namespaces(_default, active_namespaces) do
    active_namespaces
  end

  defp default_namespace_if_necessary(default, parent)
       when is_empty(default) and is_empty(parent),
       do: nil

  defp default_namespace_if_necessary(default, default), do: nil

  defp default_namespace_if_necessary(default, _parent_default) do
    safe_default_namespace = xml_safe_string(default, true)

    ~s{xmlns="#{safe_default_namespace}"}
  end

  defp xmlns_namespaces([], _known_namespaces), do: nil

  defp xmlns_namespaces(namespaces, known_namespaces) do
    namespaces
    |> Enum.sort()
    |> Enum.map(fn namespace ->
      safe_ns = xml_safe_string(namespace, true)

      safe_namespace_uri =
        namespace
        |> find_known_namespace_uri(known_namespaces)
        |> xml_safe_string(true)

      ~s{xmlns:#{safe_ns}="#{safe_namespace_uri}"}
    end)
    |> Enum.join(" ")
  end

  defp find_known_namespace_uri(_namespace, []), do: ""
  defp find_known_namespace_uri(namespace, [{namespace, uri} | _]), do: uri

  defp find_known_namespace_uri(namespace, [{_, _} | rest]) do
    find_known_namespace_uri(namespace, rest)
  end

  defp attributes(sorted_attributes, active_namespaces) do
    sorted_attributes
    |> Enum.map(fn attr -> canonicalize_attribute(attr, active_namespaces) end)
    |> Enum.join(" ")
  end

  defp open_tag(
         tag,
         active_namespaces,
         new_namespaces,
         default,
         parent_default,
         sorted_attributes,
         known_namespaces
       ) do
    tag_attributes =
      [
        default_namespace_if_necessary(default, parent_default),
        xmlns_namespaces(new_namespaces, known_namespaces),
        attributes(sorted_attributes, active_namespaces)
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")
      |> String.trim()

    case tag_attributes do
      "" ->
        "<#{tag}>"

      _ ->
        "<#{tag} #{tag_attributes}>"
    end
  end

  defp close_tag(tag), do: "</#{tag}>"

  defp tag_name(_element_name, {namespace, name}), do: "#{namespace}:#{name}"
  defp tag_name(element_name, _nsinfo), do: element_name

  defp canonicalize_attribute(
         {:xmlAttribute, _, _, {namespace, name}, _, _, _, _, value, _} = attr,
         active_namespaces
       ) do
    if namespace in active_namespaces do
      safe_namespace = atom_to_string(namespace)
      safe_name = atom_to_string(name)
      safe_value = xml_safe_string(value, true)

      ~s{#{safe_namespace}:#{safe_name}="#{safe_value}"}
    else
      bad_args = %{
        attribute: attr,
        active_namespaces: active_namespaces
      }

      raise ArgumentError, message: "attribute namespace is not active: #{inspect(bad_args)}"
    end
  end

  defp canonicalize_attribute(
         {:xmlAttribute, name, _, _, _, _, _, _, value, _},
         _active_namespaces
       ) do
    safe_name = atom_to_string(name)
    safe_value = xml_safe_string(value, true)

    ~s{#{safe_name}="#{safe_value}"}
  end
end
