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
package io.gatling.http.request

import java.io.FileInputStream

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.session.Session
import io.gatling.core.util.FastByteArrayInputStream
import io.gatling.core.util.IO._
import io.gatling.http.util.GZIPHelper

object BodyProcessors {

  val Gzip = (body: Body) => {

    val gzippedBytes = body match {
      case StringBody(string) => (session: Session) => string(session).map(GZIPHelper.gzip)
      case ByteArrayBody(byteArray) => (session: Session) => byteArray(session).map(GZIPHelper.gzip)
      case RawFileBody(file) => (session: Session) => file(session).map { f => withCloseable(new FileInputStream(f))(GZIPHelper.gzip(_)) }
      case InputStreamBody(inputStream) => (session: Session) => inputStream(session).map { withCloseable(_)(GZIPHelper.gzip(_)) }
      case _ => throw new UnsupportedOperationException(s"requestCompressor doesn't support $body")
    }

    ByteArrayBody(gzippedBytes)
  }

  def Stream(implicit configuration: GatlingConfiguration) = (body: Body) => {

    val stream = body match {
      case StringBody(string) => (session: Session) => string(session).map(s => new FastByteArrayInputStream(s.getBytes(configuration.core.encoding)))
      case ByteArrayBody(byteArray) => (session: Session) => byteArray(session).map(new FastByteArrayInputStream(_))
      case RawFileBody(file) => (session: Session) => file(session).map(new FileInputStream(_))
      case InputStreamBody(inputStream) => inputStream
      case _ => throw new UnsupportedOperationException(s"streamBody doesn't support $body")
    }

    InputStreamBody(stream)
  }
}
