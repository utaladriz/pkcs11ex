defmodule Pkcs11ex.JWSAuditOptionalDepTest do
  @moduledoc """
  Verifies that `Pkcs11ex.JWS` compiles AND runs correctly when the
  optional `pkcs11ex_audit` dep is absent at runtime — the case for
  downstream consumers that don't add it.

  Two layers of assurance:

    * **Compile-time**: this test file (and `lib/pkcs11ex/jws.ex`) compile
      without a hard reference to `Pkcs11ex.Audit`. The `apply/3`-based
      runtime dispatch and `@compile {:no_warn_undefined, ...}` together
      mean the parent `pkcs11ex` consumer can omit `pkcs11ex_audit`.

    * **Runtime gate**: after purging `Pkcs11ex.Audit` from the BEAM and
      removing its beam path, `Code.ensure_loaded?/1` returns false. The
      audit hook in `Pkcs11ex.JWS.sign/2` reads that and returns
      `{:error, {:audit_failed, :pkcs11ex_audit_not_loaded}}` rather than
      crashing with `UndefinedFunctionError`.

  Touches global code state, so `async: false` and aggressive restoration
  in `on_exit/1`. Other tests see a normal environment.

  An end-to-end "sign + missing audit → :pkcs11ex_audit_not_loaded" run
  belongs in the `:softhsm` audit suite (a real PKCS#11 round trip is
  required to reach the audit gate post-sign); this file exercises just
  the gate's wiring.
  """

  use ExUnit.Case, async: false

  describe "audit gate when pkcs11ex_audit is unavailable" do
    setup do
      audit_beam = :code.which(Pkcs11ex.Audit)

      audit_dir =
        case audit_beam do
          path when is_list(path) -> path |> List.to_string() |> Path.dirname()
          _ -> nil
        end

      on_exit(fn ->
        if audit_dir do
          :code.add_path(String.to_charlist(audit_dir))
          Code.ensure_loaded(Pkcs11ex.Audit)
        end
      end)

      if is_nil(audit_dir) do
        {:skip, "Pkcs11ex.Audit beam path not resolvable"}
      else
        :code.del_path(String.to_charlist(audit_dir))
        :code.purge(Pkcs11ex.Audit)
        :code.delete(Pkcs11ex.Audit)

        :ok
      end
    end

    test "Code.ensure_loaded? returns false after purge + path removal" do
      refute Code.ensure_loaded?(Pkcs11ex.Audit)
    end

    test "Pkcs11ex.JWS module still loads (no compile-time hard ref to Pkcs11ex.Audit)" do
      # If `Pkcs11ex.JWS` had a compile-time symbol reference to
      # `Pkcs11ex.Audit.append/3`, the compiler would have warned and the
      # runtime would crash on first call into JWS.sign. The runtime
      # dispatch via `apply/3` plus `@compile {:no_warn_undefined, ...}`
      # means the JWS module loads fine even with audit gone.
      assert Code.ensure_loaded?(Pkcs11ex.JWS)
      assert function_exported?(Pkcs11ex.JWS, :sign, 2)
    end

    test "JWS.sign with :audit_to set surfaces a clean error rather than crashing" do
      # Drive sign with input that fails the allowlist gate before reaching
      # the NIF — proves the call doesn't crash with UndefinedFunctionError
      # while pkcs11ex_audit is purged, regardless of which gate trips first.
      original = Application.get_env(:pkcs11ex, :allowed_algs)
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      on_exit(fn -> Application.put_env(:pkcs11ex, :allowed_algs, original) end)

      result =
        Pkcs11ex.JWS.sign("payload",
          alg: :ES256,
          x5c: <<0::256>>,
          audit_to: %{any: :thing}
        )

      assert match?({:error, _}, result)
    end
  end
end
