defmodule Pkcs11ex.Slot.Server do
  @moduledoc """
  GenServer that owns a single slot's PKCS#11 module + persistent session.

  One process per configured slot. State machine:

      :uninitialized ──open──▶ :open ──login──▶ :logged_in
                                │                  │
                                │                  ├─ logout ─▶ :open
                                │                  └─ timeout ─▶ :open (with reauthentication policy)
                                └─ shutdown ─▶ (terminate)

  Sessions persist for the lifetime of the GenServer (Phase 1's per-call
  open/close model is replaced here). For PIN-protected token slots this
  matches the spec's single-session-pinned model: all sign/verify calls to
  this slot serialize through this GenServer's mailbox AND through the
  session's internal mutex, so concurrent token access is impossible by
  construction.

  ## Phase 2 status

  This step ships the lifecycle plumbing. The `pin_callback` lifecycle from
  `api.md` §4.2 lands in step 2 (PIN reauth, `:reauthentication :prompt`/`:fail`,
  session timeouts). For now, the PIN is supplied at sign/verify call time.
  """

  use GenServer

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Pool

  # Default GenServer.call ceilings (ms). All overridable per-call via
  # `:call_timeout` (and per-slot via `slot_config[:call_timeout]`),
  # because cloud HSM round-trips and large-key sign operations can blow
  # past 30s under load.
  @default_call_timeout 30_000
  @default_import_timeout 60_000

  @typedoc "State machine state of the slot."
  @type slot_state :: :uninitialized | :open | :logged_in

  defstruct [
    :slot_ref,
    :worker_index,
    :slot_config,
    :module,
    :session,
    :driver_pins,
    :last_activity,
    state: :uninitialized,
    pin: nil
  ]

  # ---------- Public API ----------

  @doc """
  Start a slot server. Options:

    * `:slot_ref` — atom from `Pkcs11ex.Config.t().slots`. Required.
    * `:worker_index` — integer ≥ 1, identifying this worker within the
      slot's pool. Defaults to `1`. The supervisor passes 1..N for pool
      slots; tests and single-worker production paths use the default.
    * `:slot_config` — the keyword list for that slot. Required.
    * `:driver_pins` — the global `:driver_pins` map. Defaults to `%{}`.
    * `:name` — registered name. Defaults to the via-tuple in
      `Pkcs11ex.Slot.Registry` keyed by `{slot_ref, worker_index}`.
  """
  def start_link(opts) do
    slot_ref = Keyword.fetch!(opts, :slot_ref)
    worker_index = Keyword.get(opts, :worker_index, 1)
    name = Keyword.get(opts, :name, via({slot_ref, worker_index}))
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Sign `data` with `key_label` on the slot. PIN is supplied per call.

  Routes through `Pkcs11ex.Slot.Pool.next_worker_index/1`: for non-pool
  slots (`session_pool_size: 1` or unconfigured) always lands on worker
  1; for pool slots round-robins across the workers.

  Emits `[:pkcs11ex, :slot, :sign]` telemetry with metadata
  `%{slot_ref:, worker_index:, mechanism:}` after the call returns.
  """
  @spec sign(atom(), String.t(), atom(), iodata(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def sign(slot_ref, key_label, mechanism, data, opts \\ []) do
    idx = Pool.next_worker_index(slot_ref)

    result =
      GenServer.call(
        via({slot_ref, idx}),
        {:sign, key_label, mechanism, IO.iodata_to_binary(data), opts},
        call_timeout(slot_ref, opts)
      )

    :telemetry.execute(
      [:pkcs11ex, :slot, :sign],
      %{count: 1},
      %{slot_ref: slot_ref, worker_index: idx, mechanism: mechanism, result: result_kind(result)}
    )

    result
  end

  @doc """
  Verify a signature on the slot. Routes through pool round-robin like
  `sign/5`. Emits `[:pkcs11ex, :slot, :verify]` telemetry on the same
  shape.
  """
  @spec verify(atom(), String.t(), atom(), iodata(), binary(), keyword()) ::
          :ok | {:error, term()}
  def verify(slot_ref, key_label, mechanism, data, signature, opts \\ []) do
    idx = Pool.next_worker_index(slot_ref)

    result =
      GenServer.call(
        via({slot_ref, idx}),
        {:verify, key_label, mechanism, IO.iodata_to_binary(data), signature, opts},
        call_timeout(slot_ref, opts)
      )

    :telemetry.execute(
      [:pkcs11ex, :slot, :verify],
      %{count: 1},
      %{slot_ref: slot_ref, worker_index: idx, mechanism: mechanism, result: result_kind(result)}
    )

    result
  end

  defp result_kind(:ok), do: :ok
  defp result_kind({:ok, _}), do: :ok
  defp result_kind({:error, _}), do: :error
  defp result_kind(_), do: :other

  @doc """
  Explicit one-shot login. The PIN is consumed and dropped — not stored on
  the GenServer state.

  Always lands on worker 1: `session_pool_size > 1` is forbidden for
  `:token` slots (the only slot type where login state is observable),
  so worker 1 is the only worker that has login state worth setting.
  """
  @spec login(atom(), binary()) :: :ok | {:error, term()}
  def login(slot_ref, pin) when is_binary(pin) do
    GenServer.call(via({slot_ref, 1}), {:login, pin}, call_timeout(slot_ref, []))
  end

  @doc """
  Provisioning: import an RSA keypair + cert into the slot's token.

  Used by `mix pkcs11ex.import_p12`. **Not** a runtime API — calling this
  from a request path violates the "no software signing" non-goal because
  it implies the caller has the private-key components in software memory.

  `args` keyword list:
    * `:components` — `Pkcs11ex.Native.RsaPrivateComponents` struct
    * `:cert_der` — full DER-encoded leaf cert
    * `:subject_der` — DER-encoded subject DN (extracted from cert)
    * `:key_label` — `CKA_LABEL` for the imported private key
    * `:cert_label` — `CKA_LABEL` for the imported cert (often == `:key_label`)
    * `:id` — `CKA_ID` byte string. Empty string means "no id".

  Login follows the standard PIN priority chain (`opts[:pin]` →
  configured `:pin_callback`).
  """
  @spec import_keypair(atom(), keyword(), keyword()) :: :ok | {:error, term()}
  def import_keypair(slot_ref, args, opts \\ []) do
    case Registry.lookup(Pkcs11ex.Slot.Registry, {slot_ref, 1}) do
      [] ->
        {:error, :slot_not_found}

      [_] ->
        timeout = Keyword.get(opts, :call_timeout) || @default_import_timeout
        GenServer.call(via({slot_ref, 1}), {:import_keypair, args, opts}, timeout)
    end
  end

  @doc "Returns the slot's current state machine state (worker 1)."
  @spec status(atom()) :: slot_state()
  def status(slot_ref),
    do: GenServer.call(via({slot_ref, 1}), :status, call_timeout(slot_ref, []))

  @doc """
  Returns the slot's configured `slot_config` keyword list.

  Used by signer-ref resolution (`Pkcs11ex.sign_bytes(..., signer: {slot, key})`)
  to look up the actual `key_label` for a logical `key_ref` without needing
  to read `Application.config()` directly. The Slot.Server is the single
  source of truth for whichever slot it serves — wherever it was started
  from (the application supervisor or a test) the same lookup works.
  """
  @spec get_config(atom()) :: {:ok, keyword()} | {:error, :slot_not_found}
  def get_config(slot_ref) do
    case Registry.lookup(Pkcs11ex.Slot.Registry, {slot_ref, 1}) do
      [] -> {:error, :slot_not_found}
      [_] -> GenServer.call(via({slot_ref, 1}), :get_config, call_timeout(slot_ref, []))
    end
  end

  @doc """
  Explicit logout. The session stays open; subsequent sign calls will need a
  PIN again. Targets worker 1 — see `login/2`.
  """
  @spec logout(atom()) :: :ok | {:error, term()}
  def logout(slot_ref),
    do: GenServer.call(via({slot_ref, 1}), :logout, call_timeout(slot_ref, []))

  # GenServer.call timeout resolution. Per-call `opts[:call_timeout]` wins,
  # falls back to the application-env-configured default, finally to the
  # module default. The application env path lets operators widen the
  # ceiling globally for slow cloud HSMs without threading the opt through
  # every call site.
  defp call_timeout(_slot_ref, opts) do
    case Keyword.get(opts, :call_timeout) do
      n when is_integer(n) and n > 0 -> n
      _ -> Application.get_env(:pkcs11ex, :slot_call_timeout, @default_call_timeout)
    end
  end

  @doc false
  def via({slot_ref, worker_index})
      when is_atom(slot_ref) and is_integer(worker_index) and worker_index >= 1 do
    {:via, Registry, {Pkcs11ex.Slot.Registry, {slot_ref, worker_index}}}
  end

  # ---------- GenServer callbacks ----------

  @impl GenServer
  def init(opts) do
    slot_ref = Keyword.fetch!(opts, :slot_ref)
    worker_index = Keyword.get(opts, :worker_index, 1)
    slot_config = Keyword.fetch!(opts, :slot_config)
    driver_pins = Keyword.get(opts, :driver_pins, %{})

    state = %__MODULE__{
      slot_ref: slot_ref,
      worker_index: worker_index,
      slot_config: slot_config,
      driver_pins: driver_pins
    }

    # Module can be supplied directly (the supervisor passes a per-driver
    # shared instance to avoid the multi-`C_Initialize` problem), or loaded
    # from the driver path here when omitted (single-slot deployments and
    # standalone tests).
    case Keyword.fetch(opts, :module) do
      {:ok, module} ->
        finish_init(%{state | module: module}, slot_config)

      :error ->
        case load_module(slot_config[:driver], driver_pins) do
          {:ok, module} -> finish_init(%{state | module: module}, slot_config)
          {:error, reason} -> {:stop, {:driver_load_failed, reason}}
        end
    end
  end

  defp finish_init(state, slot_config) do
    if slot_config[:lazy] do
      {:ok, state}
    else
      {:ok, state, {:continue, :open_session}}
    end
  end

  @impl GenServer
  def handle_continue(:open_session, state) do
    case open_session(state) do
      {:ok, new_state} -> {:noreply, new_state}
      {:error, _reason} = err -> {:stop, err, state}
    end
  end

  @impl GenServer
  def handle_call({:sign, key_label, mechanism, data, opts}, _from, state) do
    case maybe_handle_expiry(state, opts) do
      {:error, reason, new_state} ->
        {:reply, {:error, reason}, new_state}

      {:ok, state} ->
        with {:ok, state} <- ensure_session_open(state),
             {:ok, state} <- ensure_logged_in(state, opts),
             mech_str = Atom.to_string(mechanism),
             {:ok, sig} <- normalize_native_result(do_sign(state, mech_str, key_label, data)) do
          {:reply, {:ok, sig}, touch_activity(state)}
        else
          {:error, _} = err -> {:reply, err, state}
        end
    end
  end

  def handle_call({:login, pin}, _from, state) when is_binary(pin) do
    cond do
      state.slot_config[:type] == :cloud_hsm ->
        {:reply, {:error, :no_pin_required}, state}

      true ->
        case ensure_session_open(state) do
          {:ok, state} ->
            case do_login(state, pin) do
              {:ok, state} -> {:reply, :ok, state}
              {:error, _} = err -> {:reply, err, state}
            end

          {:error, _} = err ->
            {:reply, err, state}
        end
    end
  end

  def handle_call({:import_keypair, args, opts}, _from, state) do
    components = Keyword.fetch!(args, :components) |> binary_components_to_lists()
    cert_der = Keyword.fetch!(args, :cert_der)
    subject_der = Keyword.fetch!(args, :subject_der)
    key_label = Keyword.fetch!(args, :key_label)
    cert_label = Keyword.get(args, :cert_label, key_label)
    id = Keyword.get(args, :id, "")

    with {:ok, state} <- ensure_session_open(state),
         {:ok, state} <- ensure_logged_in(state, opts),
         {:ok, true} <-
           safe_call(fn ->
             Native.import_rsa_private_key(state.session, key_label, id, components)
           end),
         {:ok, true} <-
           safe_call(fn ->
             Native.import_x509_certificate(state.session, cert_label, id, subject_der, cert_der)
           end) do
      {:reply, :ok, touch_activity(state)}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:verify, key_label, mechanism, data, signature, _opts}, _from, state) do
    with {:ok, state} <- ensure_session_open(state),
         mech_str = Atom.to_string(mechanism),
         result <- Native.verify_with_session(state.session, mech_str, key_label, data, signature) do
      case result do
        {:ok, true} -> {:reply, :ok, state}
        true -> {:reply, :ok, state}
        {:error, :signature_invalid} -> {:reply, {:error, :signature_invalid}, state}
        {:error, _} = err -> {:reply, err, state}
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call(:status, _from, state), do: {:reply, state.state, state}

  def handle_call(:get_config, _from, state), do: {:reply, {:ok, state.slot_config}, state}

  def handle_call(:logout, _from, state) do
    cond do
      state.slot_config[:type] == :cloud_hsm ->
        # No login state to drop on a cloud HSM slot — the slot stays
        # in :open with whatever session it has.
        {:reply, :ok, state}

      state.session == nil ->
        {:reply, :ok, %{state | state: :uninitialized, pin: nil}}

      true ->
        _ = Native.session_logout(state.session)
        {:reply, :ok, %{state | state: :open, pin: nil, last_activity: nil}}
    end
  end

  # ---------- State transitions ----------

  # Rustler 0.37 decodes `Vec<u8>` only from Erlang lists, not binaries. The
  # `RsaPrivateComponents` NifStruct's fields are `Vec<u8>`, so we convert
  # each field's binary to a list before crossing the NIF boundary.
  defp binary_components_to_lists(%Pkcs11ex.Native.RsaPrivateComponents{} = c) do
    %{
      c
      | modulus: :binary.bin_to_list(c.modulus),
        public_exponent: :binary.bin_to_list(c.public_exponent),
        private_exponent: :binary.bin_to_list(c.private_exponent),
        prime1: :binary.bin_to_list(c.prime1),
        prime2: :binary.bin_to_list(c.prime2),
        exponent1: :binary.bin_to_list(c.exponent1),
        exponent2: :binary.bin_to_list(c.exponent2),
        coefficient: :binary.bin_to_list(c.coefficient)
    }
  end

  # Wrap a NIF call so a Rustler decode exception (e.g., bad input shape)
  # surfaces as {:error, _} rather than crashing the GenServer and losing
  # the PKCS#11 login state. Cryptoki and SoftHSM keep login state at the
  # token level — restarting our resource doesn't reset that.
  defp safe_call(fun) do
    fun.()
  rescue
    e -> {:error, {:nif_raised, Exception.message(e)}}
  end

  defp ensure_session_open(%{state: :uninitialized} = state), do: open_session(state)
  defp ensure_session_open(state), do: {:ok, state}

  defp open_session(%{slot_config: cfg, module: module} = state) do
    {kind, value} = cfg[:slot_match]

    with {:ok, slot_id} <- resolve_slot_id(module, kind, value) do
      case Native.session_open(module, slot_id) do
        {:ok, session} ->
          {:ok, %{state | session: session, state: :open}}

        {:error, _} = err ->
          err
      end
    end
  end

  defp ensure_logged_in(state, opts) do
    cond do
      # Cloud HSM slots authenticate via cloud credentials (e.g., GCP Workload
      # Identity for libkmsp11), not PKCS#11 user PIN. The open session is
      # sufficient for sign/verify; login is a no-op.
      state.slot_config[:type] == :cloud_hsm -> {:ok, state}
      state.state == :logged_in -> {:ok, state}
      true -> do_login_via_priority(state, opts)
    end
  end

  # PIN priority order (shared between initial login and expiry-triggered
  # reauthentication):
  #   1. opts[:pin]              — one-shot path (tests, scripts)
  #   2. config :pin_callback    — application-supplied MFA
  #   3. {:error, :pin_required}
  #
  # The PIN never enters the GenServer's state; it lives only on this call's
  # stack frame and is dropped before the reply is sent.
  defp do_login_via_priority(state, opts) do
    case opts[:pin] do
      pin when is_binary(pin) ->
        do_login(state, pin)

      _ ->
        case fetch_callback_pin(state.slot_config[:pin_callback]) do
          {:ok, pin} -> do_login(state, pin)
          err -> err
        end
    end
  end

  defp fetch_callback_pin(nil), do: {:error, :pin_required}

  defp fetch_callback_pin({mod, fun, args}) when is_atom(mod) and is_atom(fun) and is_list(args) do
    case apply(mod, fun, args) do
      {:ok, pin} when is_binary(pin) -> {:ok, pin}
      {:error, _} = err -> err
      other -> {:error, {:pin_callback_returned, other}}
    end
  rescue
    e -> {:error, {:pin_callback_raised, Exception.message(e)}}
  end

  defp fetch_callback_pin(other), do: {:error, {:invalid_pin_callback, other}}

  defp do_login(state, pin) when is_binary(pin) do
    case Native.session_login(state.session, pin) do
      {:ok, true} ->
        {:ok, fresh_logged_in(state)}

      true ->
        {:ok, fresh_logged_in(state)}

      {:error, {:pkcs11_error, msg}} = err ->
        # PKCS#11 login state is per-token-per-application in most
        # implementations (SoftHSM, libkmsp11), not per-session as the
        # spec strictly requires. With session pooling, worker N's login
        # attempt sees the token already logged in by worker M and gets
        # CKR_USER_ALREADY_LOGGED_IN back. Treat as success: the desired
        # state (this session can run private-key ops) is achieved.
        if user_already_logged_in?(msg) do
          {:ok, fresh_logged_in(state)}
        else
          err
        end

      {:error, _} = err ->
        err
    end
  end

  # cryptoki 0.12 surfaces RvError::UserAlreadyLoggedIn with a stable
  # substring across releases — match on it rather than wiring a new
  # NIF variant for one PKCS#11 quirk.
  defp user_already_logged_in?(msg) when is_binary(msg) do
    String.contains?(msg, "already logged")
  end

  defp user_already_logged_in?(_), do: false

  defp fresh_logged_in(state),
    do: %{state | state: :logged_in, pin: nil, last_activity: monotonic_now_ms()}

  defp touch_activity(state), do: %{state | last_activity: monotonic_now_ms()}

  defp monotonic_now_ms, do: System.monotonic_time(:millisecond)

  # ---------- Inactivity / reauthentication ----------

  # Returns {:ok, state} when no expiry handling is needed (state preserved),
  # {:error, reason, new_state} when expiry triggered a state change that the
  # caller must reflect in its reply.
  defp maybe_handle_expiry(%{state: :logged_in} = state, opts) do
    if expired?(state) do
      handle_expiry(state, opts)
    else
      {:ok, state}
    end
  end

  defp maybe_handle_expiry(state, _opts), do: {:ok, state}

  defp handle_expiry(state, opts) do
    reauth = state.slot_config[:reauthentication] || :prompt
    state = drop_to_open(state)

    case reauth do
      :fail ->
        {:error, :reauthentication_required, state}

      :prompt ->
        case do_login_via_priority(state, opts) do
          {:ok, state} -> {:ok, state}
          {:error, reason} -> {:error, reason, state}
        end
    end
  end

  defp drop_to_open(state) do
    _ = safe_logout(state.session)
    %{state | state: :open, last_activity: nil, pin: nil}
  end

  defp safe_logout(nil), do: :ok

  defp safe_logout(session) do
    _ = Native.session_logout(session)
    :ok
  rescue
    _ -> :ok
  end

  defp expired?(%{last_activity: nil}), do: false

  defp expired?(%{slot_config: cfg, last_activity: last}) do
    if cfg[:type] == :token do
      timeout = current_session_timeout_ms()
      timeout > 0 and monotonic_now_ms() - last > timeout
    else
      # Cloud HSM / SoftHSM slots have no PIN — no expiry semantics needed.
      false
    end
  end

  defp current_session_timeout_ms do
    # Read directly from Application env rather than the cached
    # Pkcs11ex.Application.config/0 — operators mutating :session_timeout
    # at runtime (and tests doing the same) should take effect immediately.
    Application.get_env(:pkcs11ex, :session_timeout, 300_000)
  end

  # ---------- Helpers ----------

  defp resolve_slot_id(_module, :slot_id, id), do: {:ok, id}

  defp resolve_slot_id(module, :token_label, label) do
    case Native.list_slots(module) do
      {:ok, slots} ->
        case Enum.find(slots, &(&1.token_label == label)) do
          %{slot_id: id} -> {:ok, id}
          nil -> {:error, {:token_not_found, label}}
        end

      {:error, _} = err ->
        err
    end
  end

  defp load_module(driver, driver_pins) do
    case Map.get(driver_pins, driver) do
      nil -> Native.module_load(driver)
      sha256_hex -> Native.module_load_pinned(driver, sha256_hex)
    end
  end

  defp do_sign(state, mech_str, key_label, data),
    do: Native.sign_with_session(state.session, mech_str, key_label, data)

  # NIF returns `Result<Vec<u8>, Error>`; Rustler 0.37 encodes Vec<u8> as
  # an Erlang list, hence the IO.iodata_to_binary call here.
  defp normalize_native_result({:ok, sig}), do: {:ok, IO.iodata_to_binary(sig)}
  defp normalize_native_result({:error, _} = err), do: err
end
