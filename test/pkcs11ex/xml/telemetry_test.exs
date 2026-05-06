defmodule Pkcs11ex.XML.TelemetryTest do
  @moduledoc """
  Asserts the telemetry contract (api.md §4.2) for the XML format
  adapter:

    * `[:pkcs11ex, :sign, :start | :stop | :exception]` and
      `[:pkcs11ex, :verify, ...]` fire with `:format = :xml`,
      `:alg`, `:encoding_context = :der`, plus `:slot_ref` /
      `:key_ref` when present.
    * On verify success, `:subject_id` lands in `:stop` metadata
      (verified in `xml_softhsm_test.exs`).
    * Failures merge `:error_class` and `:error_reason` into the
      stop meta so dashboards pivot on the class atom.

  Coverage uses error paths only — error-path verifies fire the
  span the same way success ones do, so we stay HSM-free.
  """

  use ExUnit.Case, async: false

  alias Pkcs11ex.XML

  setup do
    pid = self()
    handler_id = "xml-telemetry-test-#{System.unique_integer([:positive])}"

    :telemetry.attach_many(
      handler_id,
      [
        [:pkcs11ex, :sign, :start],
        [:pkcs11ex, :sign, :stop],
        [:pkcs11ex, :sign, :exception],
        [:pkcs11ex, :verify, :start],
        [:pkcs11ex, :verify, :stop],
        [:pkcs11ex, :verify, :exception]
      ],
      fn event, measurements, metadata, _config ->
        send(pid, {:telemetry, event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    :ok
  end

  describe "[:pkcs11ex, :sign, ...]" do
    test "fires :start + :stop with :format = :xml" do
      _ = XML.sign("<doc/>", alg: :PS256, slot_id: 7, key_label: "k")

      assert_received {:telemetry, [:pkcs11ex, :sign, :start], _, start_meta}
      assert start_meta.format == :xml
      assert start_meta.alg == :PS256
      assert start_meta.encoding_context == :der
      assert start_meta.slot_ref == 7
      assert start_meta.key_ref == "k"

      assert_received {:telemetry, [:pkcs11ex, :sign, :stop], stop_measurements, stop_meta}
      assert is_integer(stop_measurements.duration)
      assert stop_meta.format == :xml
      assert stop_meta.error_class == :jws
      assert stop_meta.error_reason == :missing_x5c
    end

    test "extracts slot_ref/key_ref from a canonical :signer tuple" do
      _ = XML.sign("<doc/>", alg: :PS256, signer: {:platform, :signing})

      assert_received {:telemetry, [:pkcs11ex, :sign, :start], _, meta}
      assert meta.slot_ref == :platform
      assert meta.key_ref == :signing
    end

    test "stop meta classifies disallowed_alg as :jws" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

      _ = XML.sign("<doc/>", alg: :HS256, x5c: <<1, 2, 3>>)

      assert_received {:telemetry, [:pkcs11ex, :sign, :stop], _, stop_meta}
      assert stop_meta.error_class == :jws
      assert stop_meta.error_reason == :disallowed_alg
    end
  end

  describe "[:pkcs11ex, :verify, ...]" do
    test "fires :start + :stop carrying :byte_count and :xml class" do
      xml = "<doc/>"
      _ = XML.verify(xml)

      assert_received {:telemetry, [:pkcs11ex, :verify, :start], _, start_meta}
      assert start_meta.format == :xml

      assert_received {:telemetry, [:pkcs11ex, :verify, :stop], _, stop_meta}
      assert stop_meta.byte_count == byte_size(xml)
      assert stop_meta.error_class == :xml
      assert stop_meta.error_reason == :no_signature_element
    end
  end
end
