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
package io.gatling.http.check.header

import java.net.URLDecoder

import io.gatling.core.check.extractor._
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.validation.{ SuccessWrapper, Validation }
import io.gatling.http.HeaderNames
import io.gatling.http.response.Response

object HttpHeaderExtractor {

  def decode(headerName: String, headerValue: String)(implicit configuration: GatlingConfiguration) =
    if (headerName == HeaderNames.Location)
      URLDecoder.decode(headerValue, configuration.core.encoding)
    else
      headerValue

  def decodedHeaders(response: Response, headerName: String): Seq[String] = response.headers(headerName).map(decode(headerName, _))
}

abstract class HttpHeaderExtractor[X] extends CriterionExtractor[Response, String, X] { val criterionName = "header" }

class SingleHttpHeaderExtractor(val criterion: String, val occurrence: Int) extends HttpHeaderExtractor[String] with FindArity {

  def extract(prepared: Response): Validation[Option[String]] =
    prepared.headers(criterion).lift(occurrence).map(HttpHeaderExtractor.decode(criterion, _)).success
}

class MultipleHttpHeaderExtractor(val criterion: String) extends HttpHeaderExtractor[Seq[String]] with FindAllArity {

  def extract(prepared: Response): Validation[Option[Seq[String]]] =
    HttpHeaderExtractor.decodedHeaders(prepared, criterion).liftSeqOption.success
}

class CountHttpHeaderExtractor(val criterion: String) extends HttpHeaderExtractor[Int] with CountArity {

  def extract(prepared: Response): Validation[Option[Int]] =
    prepared.headers(criterion).liftSeqOption.map(_.size).success
}
