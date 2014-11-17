/**
 * Copyright 2011-2014 eBusiness Information, Groupe Excilys (www.ebusinessinformation.fr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gatling.recorder.http.ssl

import java.io.{ FileInputStream, InputStream, File }
import java.security.cert.X509Certificate
import java.security.{ PrivateKey, Security, KeyStore }
import javax.net.ssl.{ X509KeyManager, KeyManagerFactory, SSLContext }

import io.gatling.core.util.IO._

import scala.collection.concurrent.TrieMap
import scala.util.{ Failure, Try }

sealed trait SslServerContextFactory {

  def password: Array[Char]

  def keyStore: KeyStore

  def newServerContext(alias: String): SSLContext
}

object SslServerContextFactory {
  val GatlingPassword = "gatling"
  val Algorithm = Option(Security.getProperty("ssl.KeyManagerFactory.algorithm")).getOrElse("SunX509")
  val Protocol = "TLS"
  val KeyStoreType = "JKS"

  abstract class ImmutableFactory extends SslServerContextFactory {

    def keyStoreInitStream: InputStream

    lazy val keyStore = {
      val ks = KeyStore.getInstance(KeyStoreType)
      withCloseable(keyStoreInitStream) { ks.load(_, password) }
      ks
    }

    lazy val serverContext = {
      // Set up key manager factory to use our key store
      val kmf = KeyManagerFactory.getInstance(Algorithm)
      kmf.init(keyStore, password)

      // Initialize the SSLContext to work with our key managers.
      val serverContext = SSLContext.getInstance(Protocol)
      serverContext.init(kmf.getKeyManagers, null, null)

      serverContext
    }

    def newServerContext(alias: String): SSLContext = serverContext
  }

  object SelfSignedFactory extends ImmutableFactory {

    val GatlingSelfSignedKeyStore = "gatling.jks"

    def keyStoreInitStream: InputStream = classpathResourceAsStream(GatlingSelfSignedKeyStore)

    val password: Array[Char] = GatlingPassword.toCharArray
  }

  class ProvidedKeystoreFactory(ksFile: File, val password: Array[Char]) extends ImmutableFactory {

    def keyStoreInitStream: InputStream = new FileInputStream(ksFile)
  }

  abstract class OnTheFlyFactory extends SslServerContextFactory {

    val aliasContexts = TrieMap.empty[String, SSLContext]

    def newServerContext(alias: String): SSLContext = synchronized {
      aliasContexts.getOrElseUpdate(alias, newAliasContext(alias))
    }

    def caInfo(): Try[(PrivateKey, X509Certificate)]

    private def newAliasContext(alias: String): SSLContext =
      SslCertUtil.updateKeystoreWithNewAlias(keyStore, password, alias, caInfo) match {
        case Failure(t) => throw t
        case _ =>
          // Set up key manager factory to use our key store
          val kmf = KeyManagerFactory.getInstance(Algorithm)
          kmf.init(keyStore, password)

          // Initialize the SSLContext to work with our key manager
          val serverContext = SSLContext.getInstance(Protocol)
          serverContext.init(Array(new KeyManagerDelegate(kmf.getKeyManagers.head.asInstanceOf[X509KeyManager], alias)), null, null)
          serverContext
      }

    val password: Array[Char] = GatlingPassword.toCharArray

    lazy val keyStore = {
      val ks = KeyStore.getInstance(KeyStoreType)
      ks.load(null, null)
      ks
    }
  }

  object GatlingCAFactory extends OnTheFlyFactory {

    val DefaultCAKeyFile = "gatlingCA.key.pem"
    val DefaultCACrtFile = "gatlingCA.cert.pem"

    lazy val caInfo = SslCertUtil.getCAInfo(classpathResourceAsStream(DefaultCAKeyFile), classpathResourceAsStream(DefaultCACrtFile))
  }

  case class ProvidedCAFactory(pemKeyFile: File, pemCrtFile: File) extends OnTheFlyFactory {

    lazy val caInfo = SslCertUtil.getCAInfo(new FileInputStream(pemKeyFile), new FileInputStream(pemCrtFile))
  }
}
