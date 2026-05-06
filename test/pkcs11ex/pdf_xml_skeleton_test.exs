defmodule Pkcs11ex.PDFXMLSkeletonTest do
  @moduledoc """
  Sanity checks for the Phase 4 skeleton modules. Documents-as-tests for the
  current (deferred) behavior so the surface doesn't regress accidentally:
  both modules expose `sign/2` + `verify/2` and currently return
  `{:error, :not_implemented_in_v1}`.

  When real implementations land, these tests get replaced with the actual
  round-trip checks; the surface contract stays.
  """

  use ExUnit.Case, async: true

  describe "Pkcs11ex.PDF" do
    # `sign/2` now actually runs the pipeline (Phase 4a step 8). The skeleton
    # contract for it has moved to `Pkcs11ex.PDF.WriterTest` and the SoftHSM
    # end-to-end. We keep one assertion here to pin the surface error class
    # for callers that omit `:x5c`.
    test "sign/2 surfaces :missing_x5c when the chain isn't supplied" do
      assert {:error, :missing_x5c} =
               Pkcs11ex.PDF.sign("dummy pdf", alg: :PS256)
    end

    test "verify/2 returns :not_implemented_in_v1 (lands in step 9)" do
      assert {:error, :not_implemented_in_v1} = Pkcs11ex.PDF.verify("dummy pdf")
    end
  end

  describe "Pkcs11ex.XML" do
    test "sign/2 returns :not_implemented_in_v1" do
      assert {:error, :not_implemented_in_v1} =
               Pkcs11ex.XML.sign("<doc/>", signer: :foo, alg: :PS256)
    end

    test "verify/2 returns :not_implemented_in_v1" do
      assert {:error, :not_implemented_in_v1} = Pkcs11ex.XML.verify("<doc/>")
    end
  end
end
