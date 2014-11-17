package io.gatling.recorder.http.ssl

import io.gatling.core.util.ClassSimpleNameToString

case object HttpsMode {
  val AllHttpsModes = List(
    SelfSignedCertificate,
    ProvidedKeyStore,
    GatlingCertificateAuthority,
    CustomCertificateAuthority)
}
sealed abstract class HttpsMode(val name: String) extends ClassSimpleNameToString

case object SelfSignedCertificate extends HttpsMode("Self-signed certificate")
case object ProvidedKeyStore extends HttpsMode("Custom keystore")
case object GatlingCertificateAuthority extends HttpsMode("Gatling Certificate Authority")
case object CustomCertificateAuthority extends HttpsMode("Custom Certificate Authority")
