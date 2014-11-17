package io.gatling.recorder.http.ssl

import io.gatling.core.util.ClassSimpleNameToString

sealed abstract class HttpsMode(val name: String) extends ClassSimpleNameToString

case object HttpsMode {

  case object SelfSignedCertificate extends HttpsMode("Self-signed certificate")
  case object ProvidedKeyStore extends HttpsMode("Custom keystore")
  case object GatlingCertificateAuthority extends HttpsMode("Gatling Certificate Authority")
  case object CustomCertificateAuthority extends HttpsMode("Custom Certificate Authority")

  val AllHttpsModes = List(
    SelfSignedCertificate,
    ProvidedKeyStore,
    GatlingCertificateAuthority,
    CustomCertificateAuthority)

  def apply(s: String): HttpsMode =
    AllHttpsModes.find(_.toString == s).getOrElse {
      throw new IllegalArgumentException(s"$s is not a valid HTTPS mode")
    }
}
