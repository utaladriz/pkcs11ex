defmodule Pkcs11ex.ConfigTest do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Config
  alias Pkcs11ex.Error

  # ---------- Happy path ----------

  describe "load!/1 happy path" do
    test "returns a struct with all defaults applied for empty input" do
      config = Config.load!(env: [], check_files: false)

      assert %Config{} = config
      assert config.signature_header == "JWS-Signature"
      assert config.allowed_algs == [:PS256]
      assert config.default_slot == nil
      assert config.trust_policy == SignCore.Policy.PinnedRegistry
      assert config.session_timeout == 300_000
      assert config.driver_pins == %{}
      assert config.slots == []
      assert config.algorithms == %{}
      assert config.telemetry_prefix == [:pkcs11ex]
    end

    test "validates a representative full configuration" do
      env = [
        signature_header: "X-Signature",
        allowed_algs: [:PS256, :ES256],
        default_slot: :platform,
        slots: [
          platform: [
            type: :cloud_hsm,
            driver: "/opt/google/kmsp11/libkmsp11.so",
            keys: [signing: [label: "platform-signing-key"]]
          ],
          legal_proxy: [
            type: :token,
            driver: "/usr/lib/libeTPkcs11.so",
            slot_match: {:token_label, "Legal Proxy A"},
            pin_callback: {MyApp.Pin, :prompt, []},
            keys: [signing: [label: "proxy-signing-key", cert_label: "proxy-cert"]]
          ]
        ]
      ]

      config = Config.load!(env: env, check_files: false)

      assert config.default_slot == :platform
      assert Keyword.has_key?(config.slots, :platform)
      assert Keyword.has_key?(config.slots, :legal_proxy)
    end

    test "applies :lazy default — true for :token, false for :cloud_hsm and :soft_hsm" do
      env = [
        slots: [
          tok: [type: :token, driver: "/x", pin_callback: {M, :f, []}, keys: [k: [label: "k"]]],
          hsm: [type: :cloud_hsm, driver: "/y", keys: [k: [label: "k"]]],
          soft: [type: :soft_hsm, driver: "/z", keys: [k: [label: "k"]]]
        ]
      ]

      config = Config.load!(env: env, check_files: false)

      assert config.slots[:tok][:lazy] == true
      assert config.slots[:hsm][:lazy] == false
      assert config.slots[:soft][:lazy] == false
    end

    test "explicit :lazy overrides the type-based default" do
      env = [
        slots: [
          tok: [
            type: :token,
            driver: "/x",
            pin_callback: {M, :f, []},
            lazy: false,
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      config = Config.load!(env: env, check_files: false)
      assert config.slots[:tok][:lazy] == false
    end

    test "verify-only deployment (empty :slots) is valid" do
      assert %Config{slots: []} = Config.load!(env: [allowed_algs: [:PS256]], check_files: false)
    end
  end

  # ---------- Schema-level rejections ----------

  describe "schema validation" do
    test "rejects unknown alg in :allowed_algs" do
      assert_raise Error, ~r/invalid_config/, fn ->
        Config.load!(env: [allowed_algs: [:PS256, :HS256]], check_files: false)
      end
    end

    test "rejects unknown slot type" do
      env = [slots: [s: [type: :magic, driver: "/x"]]]

      assert_raise Error, ~r/invalid_config/, fn ->
        Config.load!(env: env, check_files: false)
      end
    end

    test "rejects missing required slot keys (:type, :driver)" do
      assert_raise Error, ~r/invalid_config/, fn ->
        Config.load!(env: [slots: [s: [driver: "/x"]]], check_files: false)
      end

      assert_raise Error, ~r/invalid_config/, fn ->
        Config.load!(env: [slots: [s: [type: :cloud_hsm]]], check_files: false)
      end
    end

    test "rejects malformed :slot_match tuple" do
      env = [slots: [s: [type: :cloud_hsm, driver: "/x", slot_match: {:slot_id, "not_a_number"}]]]

      assert_raise Error, ~r/invalid_config/, fn ->
        Config.load!(env: env, check_files: false)
      end
    end
  end

  # ---------- Cross-field invariants (api.md §1.5) ----------

  describe "invariant: :allowed_algs non-empty" do
    test "rejects empty list" do
      err =
        assert_raise Error, fn ->
          Config.load!(env: [allowed_algs: []], check_files: false)
        end

      assert err.path == [:allowed_algs]
    end
  end

  describe "invariant: :default_slot must reference :slots" do
    test "rejects unknown slot ref" do
      err =
        assert_raise Error, fn ->
          Config.load!(env: [default_slot: :nope, slots: []], check_files: false)
        end

      assert err.path == [:default_slot]
    end

    test "accepts when slot exists" do
      env = [
        default_slot: :ok,
        slots: [ok: [type: :cloud_hsm, driver: "/x", keys: [k: [label: "k"]]]]
      ]

      assert %Config{default_slot: :ok} = Config.load!(env: env, check_files: false)
    end
  end

  describe "invariant: :session_pool_size > 1 requires :cloud_hsm or :soft_hsm" do
    test "rejects pool size > 1 on a :token slot" do
      env = [
        slots: [
          t: [
            type: :token,
            driver: "/x",
            pin_callback: {M, :f, []},
            session_pool_size: 4,
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :t, :session_pool_size]
    end

    test "accepts pool size > 1 on a :cloud_hsm slot" do
      env = [
        slots: [
          h: [
            type: :cloud_hsm,
            driver: "/x",
            session_pool_size: 4,
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      assert %Pkcs11ex.Config{} = Config.load!(env: env, check_files: false)
    end

    test "accepts pool size > 1 on a :soft_hsm slot" do
      env = [
        slots: [
          s: [
            type: :soft_hsm,
            driver: "/x",
            session_pool_size: 2,
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      assert %Pkcs11ex.Config{} = Config.load!(env: env, check_files: false)
    end

    test "accepts pool size 1 (default) on any slot type" do
      env = [
        slots: [
          t: [
            type: :token,
            driver: "/x",
            pin_callback: {M, :f, []},
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      assert %Pkcs11ex.Config{} = Config.load!(env: env, check_files: false)
    end
  end

  describe "invariant: :token slot requires :pin_callback" do
    test "rejects when missing" do
      env = [slots: [t: [type: :token, driver: "/x", keys: [k: [label: "k"]]]]]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :t, :pin_callback]
    end
  end

  describe "invariant: :cloud_hsm slot forbids :pin_callback" do
    test "rejects when present" do
      env = [
        slots: [
          h: [
            type: :cloud_hsm,
            driver: "/x",
            pin_callback: {M, :f, []},
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :h, :pin_callback]
    end
  end

  describe "invariant: key must have :label or :id" do
    test "rejects when both absent" do
      env = [slots: [s: [type: :cloud_hsm, driver: "/x", keys: [k: []]]]]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :s, :keys, :k]
    end

    test "accepts :id only" do
      env = [slots: [s: [type: :cloud_hsm, driver: "/x", keys: [k: [id: <<1, 2, 3>>]]]]]

      assert %Config{} = Config.load!(env: env, check_files: false)
    end
  end

  describe "invariant: key cannot have both :cert_label and :cert_id" do
    test "rejects when both present" do
      env = [
        slots: [
          s: [
            type: :cloud_hsm,
            driver: "/x",
            keys: [k: [label: "k", cert_label: "c", cert_id: <<1>>]]
          ]
        ]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :s, :keys, :k]
    end
  end

  describe "invariant: per-slot :allowed_algs intersects with global" do
    test "rejects empty intersection" do
      env = [
        allowed_algs: [:PS256],
        slots: [
          s: [
            type: :cloud_hsm,
            driver: "/x",
            allowed_algs: [:ES256],
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots, :s, :allowed_algs]
    end

    test "accepts non-empty intersection" do
      env = [
        allowed_algs: [:PS256, :ES256],
        slots: [
          s: [
            type: :cloud_hsm,
            driver: "/x",
            allowed_algs: [:ES256],
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      assert %Config{} = Config.load!(env: env, check_files: false)
    end
  end

  describe "invariant: same driver path with different :driver_config is rejected" do
    test "rejects" do
      env = [
        slots: [
          a: [
            type: :cloud_hsm,
            driver: "/same.so",
            driver_config: "/a.yaml",
            keys: [k: [label: "k"]]
          ],
          b: [
            type: :cloud_hsm,
            driver: "/same.so",
            driver_config: "/b.yaml",
            keys: [k: [label: "k"]]
          ]
        ]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: false) end
      assert err.path == [:slots]
    end

    test "accepts when configs match (even if both nil)" do
      env = [
        slots: [
          a: [type: :cloud_hsm, driver: "/same.so", keys: [k: [label: "k"]]],
          b: [type: :cloud_hsm, driver: "/same.so", keys: [k: [label: "k"]]]
        ]
      ]

      assert %Config{} = Config.load!(env: env, check_files: false)
    end
  end

  describe "invariant: driver path must exist (when :check_files is true)" do
    @tag :tmp_dir
    test "passes when file exists", %{tmp_dir: tmp} do
      driver = Path.join(tmp, "libfake.so")
      File.write!(driver, "stub")

      env = [slots: [s: [type: :cloud_hsm, driver: driver, keys: [k: [label: "k"]]]]]

      assert %Config{} = Config.load!(env: env, check_files: true)
    end

    test "fails when file is missing" do
      env = [slots: [s: [type: :cloud_hsm, driver: "/no/such/driver.so", keys: [k: [label: "k"]]]]]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: true) end
      assert err.path == [:slots, :s, :driver]
    end
  end

  describe "invariant: :driver_pins SHA-256 must match (when :check_files is true)" do
    @tag :tmp_dir
    test "passes on match", %{tmp_dir: tmp} do
      driver = Path.join(tmp, "libfake.so")
      File.write!(driver, "hello")
      expected = :crypto.hash(:sha256, "hello") |> Base.encode16(case: :lower)

      env = [
        driver_pins: %{driver => expected},
        slots: [s: [type: :cloud_hsm, driver: driver, keys: [k: [label: "k"]]]]
      ]

      assert %Config{} = Config.load!(env: env, check_files: true)
    end

    @tag :tmp_dir
    test "fails on mismatch", %{tmp_dir: tmp} do
      driver = Path.join(tmp, "libfake.so")
      File.write!(driver, "hello")
      bogus = String.duplicate("0", 64)

      env = [
        driver_pins: %{driver => bogus},
        slots: [s: [type: :cloud_hsm, driver: driver, keys: [k: [label: "k"]]]]
      ]

      err = assert_raise Error, fn -> Config.load!(env: env, check_files: true) end
      assert {:driver_pin_mismatch, ^driver} = err.reason
    end

    @tag :tmp_dir
    test "case-insensitive on the configured pin", %{tmp_dir: tmp} do
      driver = Path.join(tmp, "libfake.so")
      File.write!(driver, "hello")
      upper = :crypto.hash(:sha256, "hello") |> Base.encode16(case: :upper)

      env = [
        driver_pins: %{driver => upper},
        slots: [s: [type: :cloud_hsm, driver: driver, keys: [k: [label: "k"]]]]
      ]

      assert %Config{} = Config.load!(env: env, check_files: true)
    end
  end
end
