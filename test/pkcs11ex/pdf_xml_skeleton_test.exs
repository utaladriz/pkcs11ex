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

  describe "SignCore.PDF" do
    # `sign/2` now actually runs the pipeline (Phase 4a step 8). The skeleton
    # contract for it has moved to `SignCore.PDF.WriterTest` and the SoftHSM
    # end-to-end. We keep one assertion here to pin the surface error class
    # for callers that omit `:x5c`.
    test "sign/2 surfaces :missing_x5c when the chain isn't supplied" do
      assert {:error, :missing_x5c} =
               Pkcs11ex.PDF.sign("dummy pdf", alg: :PS256)
    end

    test "verify/2 surfaces :no_signature when there is no /Sig dict" do
      assert {:error, :no_signature} = Pkcs11ex.PDF.verify("dummy pdf")
    end
  end

  describe "SignCore.XML" do
    # `sign/2` runs the pipeline now (Phase 4b.1.5). Skeleton contract
    # has moved to the XML unit + :softhsm tests; here we just pin
    # the surface error class for callers that omit `:x5c`.
    test "sign/2 surfaces :missing_x5c when the chain isn't supplied" do
      assert {:error, :missing_x5c} = Pkcs11ex.XML.sign("<doc/>", alg: :PS256)
    end

    test "verify/2 surfaces :no_signature_element when there is no <ds:Signature>" do
      assert {:error, :no_signature_element} = Pkcs11ex.XML.verify("<doc/>")
    end
  end
end
