defmodule Pkcs11ex.JWSAuditTest do
  @moduledoc """
  `Pkcs11ex.JWS.sign/2`'s `:audit_to` hook — opt-in audit-log integration.

  When the caller threads an `audit` handle through `:audit_to`, every
  successful sign appends an entry to the chain carrying the JWS string,
  the signer ref, the payload SHA-256, the alg, and a timestamp.
  Off by default; if audit append fails, the sign call returns
  `{:error, {:audit_failed, reason}}` so the caller knows the JWS was
  produced but not recorded.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Audit
  alias Pkcs11ex.Audit.Storage.InMemory
  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server

  setup_all do
    driver = Pkcs11ex.Test.SoftHSM.driver_path()
    softhsm2_util = System.find_executable("softhsm2-util")

    cond do
      is_nil(driver) -> {:skip, "SoftHSM2 driver not installed"}
      is_nil(softhsm2_util) -> {:skip, "softhsm2-util CLI not on PATH"}
      true -> {:ok, driver: driver, softhsm2_util: softhsm2_util}
    end
  end

  setup %{driver: driver, softhsm2_util: softhsm2_util} do
    suffix = System.unique_integer([:positive])
    token_label = "pkcs11ex-jws-audit-#{suffix}"
    key_label = "jws-audit-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)
    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("jws_audit_slot_#{suffix}")

    slot_config = [
      type: :token,
      driver: driver,
      slot_match: {:slot_id, slot_id},
      pin_callback: nil,
      keys: [signing: [label: key_label]],
      lazy: true,
      reauthentication: :prompt
    ]

    {:ok, _} =
      start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

    audit_name = :"jws_audit_#{suffix}"
    {:ok, _} = start_supervised({InMemory, name: audit_name})
    audit = Audit.new(InMemory, audit_name)

    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

    # Any valid X.509 satisfies the JWS sign-side x5c requirement; the
    # audit hook doesn't check cert validity.
    rsa_key = X509.PrivateKey.new_rsa(2048)
    leaf = X509.Certificate.self_signed(rsa_key, "/CN=jws-audit-test")
    leaf_der = X509.Certificate.to_der(leaf)

    {:ok, slot_ref: slot_ref, pin: user_pin, audit: audit, leaf_der: leaf_der}
  end

  describe ":audit_to opt" do
    test "appends a JWS-signed entry after a successful sign", ctx do
      payload = "sign me with audit"

      assert {:ok, jws} =
               Pkcs11ex.JWS.sign(payload,
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 pin: ctx.pin,
                 x5c: ctx.leaf_der,
                 audit_to: ctx.audit
               )

      assert {:ok, entry} = Audit.head(ctx.audit)
      assert entry.payload.kind == :jws_signed
      assert entry.payload.jws == jws
      assert entry.payload.alg == :PS256
      assert entry.payload.signer == {ctx.slot_ref, :signing}
      assert entry.payload.payload_hash == :crypto.hash(:sha256, payload)
      assert %DateTime{} = entry.payload.signed_at
    end

    test "without :audit_to, no audit entries are appended", ctx do
      assert {:error, :empty} = Audit.head(ctx.audit)

      {:ok, _jws} =
        Pkcs11ex.JWS.sign("no audit",
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          pin: ctx.pin,
          x5c: ctx.leaf_der
        )

      assert {:error, :empty} = Audit.head(ctx.audit)
    end

    test "multiple signs build a verifiable chain of jws_signed entries", ctx do
      payloads = ["a", "b", "c"]

      jwses =
        Enum.map(payloads, fn p ->
          {:ok, jws} =
            Pkcs11ex.JWS.sign(p,
              signer: {ctx.slot_ref, :signing},
              alg: :PS256,
              pin: ctx.pin,
              x5c: ctx.leaf_der,
              audit_to: ctx.audit
            )

          jws
        end)

      assert :ok = Audit.verify(ctx.audit)

      Enum.with_index(payloads, 1)
      |> Enum.each(fn {p, seq} ->
        assert {:ok, entry} = Audit.at(ctx.audit, seq)
        assert entry.payload.payload_hash == :crypto.hash(:sha256, p)
        assert entry.payload.jws == Enum.at(jwses, seq - 1)
      end)
    end

    test ":audit_extra fields merge into the entry payload", ctx do
      assert {:ok, _jws} =
               Pkcs11ex.JWS.sign("with extras",
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 pin: ctx.pin,
                 x5c: ctx.leaf_der,
                 audit_to: ctx.audit,
                 audit_extra: %{request_id: "abc-123", actor: "ubaldo"}
               )

      {:ok, entry} = Audit.head(ctx.audit)
      assert entry.payload.request_id == "abc-123"
      assert entry.payload.actor == "ubaldo"
      # Base fields still present
      assert entry.payload.kind == :jws_signed
    end

    test "audit append failure surfaces as an error", ctx do
      # Point the audit at a never-started storage name. Any access via
      # InMemory's Agent calls then exits with :noproc; the JWS sign call
      # propagates the failure rather than silently producing an
      # un-recorded JWS.
      bad_audit = Audit.new(InMemory, :no_such_storage_for_audit_test)

      result =
        try do
          Pkcs11ex.JWS.sign("data",
            signer: {ctx.slot_ref, :signing},
            alg: :PS256,
            pin: ctx.pin,
            x5c: ctx.leaf_der,
            audit_to: bad_audit
          )
        catch
          :exit, _ -> :exit
        end

      # Either an {:error, {:audit_failed, _}} return OR an :exit from the
      # noproc on the dead storage Agent — both prove the caller doesn't
      # silently get a JWS without an audit entry.
      refute match?({:ok, _}, result)
    end
  end
end
