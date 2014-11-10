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

import java.io.{ File => JFile, InputStream }

import com.ning.http.client.RequestBuilder
import com.ning.http.client.generators.InputStreamBodyGenerator

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.session.{ Expression, Session }
import io.gatling.core.util.IO._
import io.gatling.core.validation.Validation

object ELFileBody {
  def apply(filePath: Expression[String]) = StringBody(ELFileBodies.asString(filePath))
}

trait Body {
  def setBody(requestBuilder: RequestBuilder, session: Session): Validation[RequestBuilder]
}

case class StringBody(string: Expression[String]) extends Body {

  def asBytes(implicit configuration: GatlingConfiguration): ByteArrayBody = {
    val bytes = (session: Session) => string(session).map(_.getBytes(configuration.core.charset))
    ByteArrayBody(bytes)
  }

  def setBody(requestBuilder: RequestBuilder, session: Session): Validation[RequestBuilder] = string(session).map(requestBuilder.setBody)
}

object RawFileBody {

  def apply(filePath: Expression[String]) = new RawFileBody(RawFileBodies.asFile(filePath))

  def unapply(b: RawFileBody) = Some(b.file)
}

class RawFileBody(val file: Expression[JFile]) extends Body {

  def asString(implicit configuration: GatlingConfiguration): StringBody = {
    val string = file.map(f => f.toString(configuration.core.charset))
    StringBody(string)
  }

  def asBytes: ByteArrayBody = {
    val bytes = file.map(f => f.toByteArray())
    ByteArrayBody(bytes)
  }

  def setBody(requestBuilder: RequestBuilder, session: Session): Validation[RequestBuilder] = file(session).map(requestBuilder.setBody)
}

case class ByteArrayBody(bytes: Expression[Array[Byte]]) extends Body {
  def setBody(requestBuilder: RequestBuilder, session: Session): Validation[RequestBuilder] = bytes(session).map(requestBuilder.setBody)
}

case class InputStreamBody(is: Expression[InputStream]) extends Body {
  def setBody(requestBuilder: RequestBuilder, session: Session): Validation[RequestBuilder] = is(session).map(is => requestBuilder.setBody(new InputStreamBodyGenerator(is)))
}
