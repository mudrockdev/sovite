defmodule Sovite.TLS.ACME.CSR do
  @moduledoc """
  Builds PKCS #10 certificate signing requests (RFC 2986) for ACME: the
  first name as the subject's common name, and every name in a
  subjectAltName extension request.
  """

  @ec_public_key {1, 2, 840, 10_045, 2, 1}
  @ecdsa_sha256 {1, 2, 840, 10_045, 4, 3, 2}
  @extension_request {1, 2, 840, 113_549, 1, 9, 14}

  @doc "Returns the DER-encoded CSR for `names`, signed with the EC `key`."
  @spec build([String.t(), ...], tuple()) :: binary()
  def build([first | _] = names, {:ECPrivateKey, _, _, params, point, _} = key) do
    san =
      :public_key.der_encode(
        :SubjectAltName,
        Enum.map(names, &{:dNSName, String.to_charlist(&1)})
      )

    extensions = :public_key.der_encode(:Extensions, [{:Extension, {2, 5, 29, 17}, false, san}])

    info =
      {:CertificationRequestInfo, :v1,
       {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, first}}]]},
       {:CertificationRequestInfo_subjectPKInfo,
        {:CertificationRequestInfo_subjectPKInfo_algorithm, @ec_public_key,
         {:asn1_OPENTYPE, :public_key.der_encode(:EcpkParameters, params)}}, point},
       [{:AttributePKCS10, @extension_request, [{:asn1_OPENTYPE, extensions}]}]}

    signature =
      :public_key.sign(:public_key.der_encode(:CertificationRequestInfo, info), :sha256, key)

    :public_key.der_encode(
      :CertificationRequest,
      {:CertificationRequest, info,
       {:CertificationRequest_signatureAlgorithm, @ecdsa_sha256, :asn1_NOVALUE}, signature}
    )
  end
end
