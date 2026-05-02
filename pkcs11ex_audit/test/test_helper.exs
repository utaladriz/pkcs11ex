excludes =
  case System.get_env("PKCS11EX_TSA_TESTS") do
    val when val in ["1", "true", "yes"] ->
      []

    _ ->
      IO.puts(
        "[pkcs11ex_audit] :tsa-tagged tests excluded; set PKCS11EX_TSA_TESTS=1 " <>
          "to run live RFC 3161 integration tests against a real TSA."
      )

      [tsa: true]
  end

ExUnit.start(exclude: excludes)
