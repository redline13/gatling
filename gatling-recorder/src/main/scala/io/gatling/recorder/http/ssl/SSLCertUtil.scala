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

import java.io._
import java.math.BigInteger
import java.security.{ KeyPairGenerator, KeyStore, PrivateKey }
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.TimeUnit
import javax.security.auth.x500.X500Principal

import scala.util.Try

import com.typesafe.scalalogging.StrictLogging
import io.gatling.core.util.IO.withCloseable
import org.bouncycastle.cert.{ X509CertificateHolder, X509v3CertificateBuilder }
import org.bouncycastle.cert.jcajce.{ JcaX509CertificateConverter, JcaX509CertificateHolder }
import org.bouncycastle.openssl.{ PEMKeyPair, PEMParser }
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

/**
 * Utility class to create SSL server certificate on the fly for the recorder keystore
 */
object SslCertUtil extends StrictLogging {

  def readPEM(file: InputStream): Any = withCloseable(new PEMParser(new InputStreamReader(file))) { _.readObject }

  def getCAInfo(keyFile: InputStream, crtFile: InputStream): Try[(PrivateKey, X509Certificate)] =
    Try {
      val keyInfo = readPEM(keyFile).asInstanceOf[PEMKeyPair].getPrivateKeyInfo
      val certHolder = readPEM(crtFile).asInstanceOf[X509CertificateHolder]
      val privateKey = new JcaPEMKeyConverter().getPrivateKey(keyInfo)
      val certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)

      (privateKey, certificate)
    }

  def updateKeystoreWithNewAlias(keyStore: KeyStore, password: Array[Char], alias: String, caInfo: Try[(PrivateKey, X509Certificate)]): Try[KeyStore] =
    for {
      (caKey, caCrt) <- caInfo
      (csr, privKey) <- createCSR(alias)
      servCrt <- createServerCert(caKey, caCrt, csr)
      updatedKeyStore <- addNewKeystoreEntry(keyStore, password, servCrt, privKey, caCrt, alias)
    } yield updatedKeyStore

  private def createCSR(dnHostName: String): Try[(PKCS10CertificationRequest, PrivateKey)] =
    Try {
      val kpGen = KeyPairGenerator.getInstance("RSA")
      kpGen.initialize(1024)
      val pair = kpGen.generateKeyPair
      val dn = s"C=FR, ST=Val de marne, O=GatlingCA, OU=Gatling, CN=$dnHostName"
      val builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), pair.getPublic)
      val signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate)
      val pkcs10CR = builder.build(signer)
      (pkcs10CR, pair.getPrivate)
    }

  private def createServerCert(keyCA: PrivateKey, certCA: X509Certificate, csr: PKCS10CertificationRequest): Try[X509Certificate] =
    Try {
      val now = System.currentTimeMillis
      val certBuilder = new X509v3CertificateBuilder(
        new JcaX509CertificateHolder(certCA).getSubject,
        BigInteger.valueOf(now),
        new Date(now),
        new Date(now + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS)), // cert validity duration
        csr.getSubject,
        csr.getSubjectPublicKeyInfo)
      val signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyCA)
      new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer))
    }

  private def addNewKeystoreEntry(keyStore: KeyStore, password: Array[Char], servCert: X509Certificate, privKey: PrivateKey, certCA: X509Certificate, alias: String): Try[KeyStore] =
    Try {
      keyStore.setCertificateEntry(alias, servCert)
      keyStore.setKeyEntry(alias, privKey, password, Array(servCert, certCA))
      keyStore
    }
}
