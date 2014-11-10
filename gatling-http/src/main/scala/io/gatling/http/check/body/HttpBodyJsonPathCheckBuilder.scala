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
package io.gatling.http.check.body

import com.typesafe.scalalogging.StrictLogging

import io.gatling.core.check.{ DefaultMultipleFindCheckBuilder, Preparer }
import io.gatling.core.check.extractor.jsonpath._
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.json.{ Jackson, Boon }
import io.gatling.core.session.{ Expression, RichExpression }
import io.gatling.core.validation.{ FailureWrapper, SuccessWrapper }
import io.gatling.http.check.{ HttpCheck, HttpCheckBuilders }
import io.gatling.http.response._

trait HttpBodyJsonPathOfType {
  self: HttpBodyJsonPathCheckBuilder[String] =>

  def ofType[X: JsonFilter] = new HttpBodyJsonPathCheckBuilder[X](path)
}

object HttpBodyJsonPathCheckBuilder extends StrictLogging {

  val CharsParsingThreshold = 1000000

  def handleParseException[R](block: R => Any) = (response: R) =>
    try {
      block(response).success
    } catch {
      case e: Exception =>
        val message = s"Could not parse response into a JSON object: ${e.getMessage}"
        logger.info(message, e)
        message.failure
    }

  def Preparer(implicit configuration: GatlingConfiguration): Preparer[Response, Any] =
    if (configuration.core.extract.jsonPath.preferJackson)
      handleParseException { response =>
        Jackson.parse(response.body.stream, response.charset)
      }
    else
      handleParseException { response =>
        if (response.bodyLength <= CharsParsingThreshold)
          Boon.parse(response.body.string)
        else
          Jackson.parse(response.body.stream, response.charset)
      }

  val BoonResponseBodyUsageStrategy = new ResponseBodyUsageStrategy {
    def bodyUsage(bodyLength: Int) =
      if (bodyLength <= CharsParsingThreshold)
        StringResponseBodyUsage
      else
        InputStreamResponseBodyUsage
  }

  val JacksonResponseBodyUsageStrategy = new ResponseBodyUsageStrategy {
    def bodyUsage(bodyLength: Int) =
      if (bodyLength <= CharsParsingThreshold)
        ByteArrayResponseBodyUsage
      else
        InputStreamResponseBodyUsage
  }

  def ResponseBodyUsageStrategy(implicit configuration: GatlingConfiguration) =
    if (configuration.core.extract.jsonPath.preferJackson) JacksonResponseBodyUsageStrategy
    else BoonResponseBodyUsageStrategy

  def jsonPath(path: Expression[String]) = new HttpBodyJsonPathCheckBuilder[String](path) with HttpBodyJsonPathOfType
}

class HttpBodyJsonPathCheckBuilder[X: JsonFilter](private[body] val path: Expression[String])
    extends DefaultMultipleFindCheckBuilder[HttpCheck, Response, Any, X](
      HttpCheckBuilders.bodyExtender(HttpBodyJsonPathCheckBuilder.ResponseBodyUsageStrategy),
      HttpBodyJsonPathCheckBuilder.Preparer) {

  def findExtractor(occurrence: Int) = path.map(new SingleJsonPathExtractor(_, occurrence))
  def findAllExtractor = path.map(new MultipleJsonPathExtractor(_))
  def countExtractor = path.map(new CountJsonPathExtractor(_))
}
