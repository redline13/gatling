package io.gatling.recorder.http.ssl

import io.gatling.core.util.ClassSimpleNameToString

object KeyStoreType {
  val AllKeyStoreTypes = List(JKS)
}
sealed abstract class KeyStoreType(val name: String) extends ClassSimpleNameToString

case object JKS extends KeyStoreType("JKS")
